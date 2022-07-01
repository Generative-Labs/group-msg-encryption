package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"os"
	"time"
)

/*
群消息加密逻辑：
1.UserA 加入群组后 生成 ed25519 的 pub/pri 密钥
2.向群内每个成员单独发送 生成的pub ，收到UserA消息的用户按格式：UserId:{groupID:{UserAID:{SignedPub:pub,ChanKey:""}}} 把消息保存到client/node(db)
3.UserA 发送消息:
	a. 用上面第一步生成的pub + salt 生成 ChanKey
	b.用 a 生成的ChanKey+salt 生成  newChanKey 和消息密钥 AD
	c. newChanKey加密后按格式  UserId:{group:{SignedPub:pub,SignedPir:pri,ChanKey:"newChanKey"}} 保存到client
	d. 用消息密钥 AD 加密消息--> 使用SignedPir 给加密后的消息加签---->发送消息
4. 群成员收到消息：
	a. 从Node/client 获取 UserA 的ChanKey&pub
	b. 如果ChanKey 不存在，用上a 获取的 pub + salt 生成 ChanKey
	c. 用 b 生成的ChanKey+salt 生成  newChanKey 和消息密钥 AD
	d. 用pub为消息验签--成功--->使用 消息密钥 AD 解密消息
	e. newChanKey加密后按格式  UserId:{groupID:{SignedPub:pub,ChanKey:"newChanKey"}} 保存到client/node(db)
*/

var userInfo map[string]*User

func init() {
	userInfo = make(map[string]*User)
	userInfo["user_1"] = buildUser("user_1")
	userInfo["user_2"] = buildUser("user_2")
	userInfo["user_3"] = buildUser("user_3")
	userInfo["user_4"] = buildUser("user_4")
}

func buildUser(id string) *User {
	var user *User
	user = &User{
		Person: buildPerson(),
		UserID: id,
	}
	return user
}

func buildPerson() *Person {
	a := &Person{}
	a.IdentityPri, a.IdentityPub = XGetCurve25519KeypPair()
	a.SignedPri, a.SignedPub = XGetCurve25519KeypPair()
	a.OneTimePri, a.OneTimePub = XGetCurve25519KeypPair()
	return a
}

type DataEvent struct {
	Data  interface{}
	Topic string
}

// DataChannel 是一个能接收 DataEvent 的 channel
type DataChannel chan DataEvent

// DataChannelSlice 是一个包含 DataChannels 数据的切片
type DataChannelSlice []DataChannel

type Group struct {
	GroupID     string
	OwnerID     string
	MemberState map[string]bool
	ch          map[string]chan DataEvent
	subscribers map[string]DataChannelSlice
}

func NewGroup(user *User) *Group {
	g := &Group{
		GroupID:     user.UserID + "_group",
		OwnerID:     user.UserID,
		MemberState: make(map[string]bool),
		ch:          make(map[string]chan DataEvent),
		subscribers: make(map[string]DataChannelSlice),
	}
	go g.LoopEvent()
	fmt.Println("添加用户...")
	g.Join(user)
	return g
}

func (g *Group) Subscribe(topic string, ch DataChannel) {
	fmt.Println("Subscribe start", topic)
	if prev, found := g.subscribers[topic]; found {
		g.subscribers[topic] = append(prev, ch)
	} else {
		g.subscribers[topic] = append([]DataChannel{}, ch)
	}
	fmt.Println("Subscribe success")
	return
}

func (g *Group) Publish(topic string, data interface{}) {
	if chans, found := g.subscribers[topic]; found {
		// 这样做是因为切片引用相同的数组，即使它们是按值传递的
		// 因此我们正在使用我们的元素创建一个新切片，从而正确地保持锁定
		channels := append(DataChannelSlice{}, chans...)
		go func(data DataEvent, dataChannelSlices DataChannelSlice) {
			for _, ch := range dataChannelSlices {
				ch <- data
			}
		}(DataEvent{Data: data, Topic: topic}, channels)
	}
	return
}

// 加入群组
func (g *Group) Join(user *User) {
	// 先创建 用户 join topic
	if user.GroupTopic == nil {
		user.GroupTopic = make(map[string]map[string]chan DataEvent)
	}
	if user.GroupTopic[g.GroupID] == nil {
		user.GroupTopic[g.GroupID] = make(map[string]chan DataEvent)
	}
	//  用户 先订阅 join topic
	user.GroupTopic[g.GroupID]["join"] = make(chan DataEvent)
	fmt.Println("group_id:", g.GroupID, "user_id:", user.UserID)
	g.Subscribe("join", user.GroupTopic[g.GroupID]["join"])
	fmt.Printf("join: %#v \n", g.subscribers["join"])
	//  用户 再订阅 group-id topic 用来发消息
	user.GroupTopic[g.GroupID]["group-"+g.GroupID] = make(chan DataEvent)
	g.Subscribe("group-"+g.GroupID, user.GroupTopic[g.GroupID]["group-"+g.GroupID])
	//  用户 再订阅 leave topic 用来接收退出信息 离开
	user.GroupTopic[g.GroupID]["group-"+g.GroupID+"-leave"] = make(chan DataEvent)
	g.Subscribe("group-"+g.GroupID+"-leave", user.GroupTopic[g.GroupID]["group-"+g.GroupID+"-leave"])
	g.copyGroupMemberKey(user)
	g.MemberState[user.UserID] = true

	g.sendJoinTopic(user, "join")
	return
}

func (g *Group) copyGroupMemberKey(user *User) {
	for userId, _ := range g.MemberState {
		if user.GroupMemberKey == nil {
			user.GroupMemberKey = make(map[string]map[string]*GroupKey)
		}
		if user.GroupMemberKey[g.GroupID] == nil {
			user.GroupMemberKey[g.GroupID] = make(map[string]*GroupKey)
		}
		user.GroupMemberKey[g.GroupID][userId] = &GroupKey{
			UserID:    userId,
			ChanKey:   GetUser(userId).GroupMsgKey[g.GroupID].ChanKey,
			SignedPub: GetUser(userId).GroupMsgKey[g.GroupID].SignedPub,
			SignedPir: nil,
		}
	}
	return
}

func (g *Group) sendJoinTopic(user *User, key string) { // 一对一，单独发送比较好
	if user.GroupMsgKey == nil {
		user.GroupMsgKey = make(map[string]*GroupKey)
	}
	user.GroupMsgKey[g.GroupID] = &GroupKey{UserID: user.UserID}
	user.GroupMsgKey[g.GroupID].ChanKey = KDF([]byte(g.GroupID + "-" + user.UserID + key)) // 使用 SignedPub  生成ChanKey
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("生成密钥失败：", err)
		return
	}
	user.GroupMsgKey[g.GroupID].SignedPir = private
	user.GroupMsgKey[g.GroupID].SignedPub = public
	// 发送加入群组信息  (这里测试demo，是消息广播发送，实际改成一对一,只发送SignedPub)
	g.Publish("join", &GroupKey{UserID: user.UserID, SignedPub: user.GroupMsgKey[g.GroupID].SignedPub, ChanKey: user.GroupMsgKey[g.GroupID].ChanKey})
	return
}

func (g *Group) Leave(user *User) {
	if _, ok := g.MemberState[user.UserID]; !ok { // 用户不存在
		return
	}
	delete(g.MemberState, user.UserID)
	// 发送推群消息
	g.Publish("group-"+g.GroupID+"-leave", "Leave")
	return
}

func (g *Group) SendMsg(user *User, msg string) {
	if _, ok := g.MemberState[user.UserID]; !ok { // 用户不存在
		return
	}
	fmt.Println("用户：", user.UserID, " 开始发消息")
	fmt.Println("用户：", user.UserID, "ChanKey:", base64.StdEncoding.EncodeToString(user.GroupMsgKey[g.GroupID].ChanKey[:]))
	salt := [32]byte{} // TODO::
	key := SaltKDF(user.GroupMsgKey[g.GroupID].ChanKey[:], salt)
	fmt.Println("用户：", user.UserID, "key:", base64.StdEncoding.EncodeToString(key[:]))
	ChanKey := key[:32]
	fmt.Println("用户：", user.UserID, "new-ChanKey:", base64.StdEncoding.EncodeToString(ChanKey[:]))
	b2arr32 := func(b []byte) [32]byte {
		a := [32]byte{}
		for i, d := range b {
			a[i] = d
		}
		return a
	}
	user.GroupMsgKey[g.GroupID].ChanKey = b2arr32(ChanKey)
	ad := key[32:]
	fmt.Println("用户：", user.UserID+" 获取消息密钥:", base64.StdEncoding.EncodeToString(ad))
	text := "我是 " + user.UserID + " 我发送的消息:" + msg
	sendMsg := EncryptedMsg(user, ad, text)
	sendMsg.Signature = ed25519.Sign(user.GroupMsgKey[g.GroupID].SignedPir[:], sendMsg.Msg)
	sendMsg.UserID = user.UserID
	g.Publish("group-"+g.GroupID, sendMsg)
	return

}

func (g *Group) LoopEvent() {
	for {
		for userId, state := range g.MemberState {
			if state {
				go func(userId string) {
					for {
						select {
						case join := <-GetUser(userId).GroupTopic[g.GroupID]["join"]:
							fmt.Println("用户：" + userId + " 收到 join 消息 \n")
							gk := join.Data.(*GroupKey)
							if GetUser(userId).GroupMemberKey == nil {
								GetUser(userId).GroupMemberKey = make(map[string]map[string]*GroupKey)
							}
							if GetUser(userId).GroupMemberKey[g.GroupID] == nil {
								GetUser(userId).GroupMemberKey[g.GroupID] = make(map[string]*GroupKey)
							}
							GetUser(userId).GroupMemberKey[g.GroupID][gk.UserID] = &GroupKey{
								UserID:    gk.UserID,
								ChanKey:   gk.ChanKey,
								SignedPub: gk.SignedPub,
								SignedPir: gk.SignedPir,
							}
							fmt.Println("用户："+userId+" 处理 join 消息：", "新用户：", gk.UserID, "ChanKey:", base64.StdEncoding.EncodeToString(gk.ChanKey[:]), " \n")
						case <-GetUser(userId).GroupTopic[g.GroupID]["group-"+g.GroupID+"-leave"]:
							fmt.Println("用户：" + userId + "收到 leave 消息 \n")
							GetUser(userId).GroupMsgKey = nil
							g.sendJoinTopic(GetUser(userId), "reset")
						case msg := <-GetUser(userId).GroupTopic[g.GroupID]["group-"+g.GroupID]:
							fmt.Println("用户：" + userId + "收到 Message 消息 \n")
							message := msg.Data.(Message)
							if !ed25519.Verify(GetUser(userId).GroupMemberKey[g.GroupID][message.UserID].SignedPub[:], message.Msg, message.Signature) {
								fmt.Println("用户：" + userId + "消息签名验证失败！")
							} else {
								fmt.Println("用户："+userId+"解析 Message 消息，ChanKey：", base64.StdEncoding.EncodeToString(GetUser(userId).GroupMemberKey[g.GroupID][message.UserID].ChanKey[:]))
								key := SaltKDF(GetUser(userId).GroupMemberKey[g.GroupID][message.UserID].ChanKey[:], [32]byte{})
								fmt.Println("用户：", userId, "key-Message:", base64.StdEncoding.EncodeToString(key[:]))
								input := key[:32]
								fmt.Println("用户：", userId, "new-ChanKey-Message:", base64.StdEncoding.EncodeToString(input[:]))
								b2arr32 := func(b []byte) [32]byte {
									a := [32]byte{}
									for i, d := range b {
										a[i] = d
									}
									return a
								}
								GetUser(userId).GroupMemberKey[g.GroupID][message.UserID].ChanKey = b2arr32(input)
								ad := key[32:]
								fmt.Println("用户：", userId+" 获取消息密钥-Message:", base64.StdEncoding.EncodeToString(ad))
								DecryptMsg(ad, message.Msg)
							}
						}
					}
				}(userId)
			}

		}
	}

}

type GroupKey struct {
	UserID    string
	ChanKey   [32]byte
	SignedPub []byte //已签名的预共享密钥//SPK
	SignedPir []byte //已签名的预共享密钥//SPK
}

type User struct {
	*Person
	UserID         string
	ConsultKey     []byte // 协商密钥
	MsgRoot        map[string][32]byte
	GroupMsgRoot   map[string][32]byte
	GroupMemberKey map[string]map[string]*GroupKey      // 群成员信息
	GroupTopic     map[string]map[string]chan DataEvent // 群topic 信息
	GroupMsgKey    map[string]*GroupKey                 // 群消息key
}

type Message struct {
	Msg              []byte   // 消息
	UserIdentityPub  [32]byte // 消息发送者的 身份密钥对//IPK
	UserEphemeralPub [32]byte // 消息发送者的 临时密钥对//EPK
	Head             []byte   // 棘轮公钥
	Signature        []byte
	UserID           string
}

type MessageNode struct {
	DHNext   []byte
	KDFNext  []byte
	DH       []byte
	KDFInput [32]byte
}

type Person struct {
	IdentityPri  [32]byte //身份密钥对//IPK
	IdentityPub  [32]byte
	SignedPri    [32]byte //已签名的预共享密钥//SPK
	SignedPub    [32]byte
	OneTimePri   [32]byte //一次性预共享密钥//OPK
	OneTimePub   [32]byte
	EphemeralPri [32]byte //一个临时密钥对//EPK  (用于产生kdf的数据加盐)
	EphemeralPub [32]byte
	DH1          [32]byte
	DH2          [32]byte
	DH3          [32]byte
	DH4          [32]byte

	// DH1-4 生产 X3DH
	//DH1 = DH(IPK-A私钥, SPK-B公钥)
	//DH2 = DH(EPK-A私钥, IPK-B公钥)
	//DH3= DH(EPK-A私钥, SPK-B公钥)
	//DH4 = DH(IPK-A私钥, OPK--B公钥)
}

// Send 初始化发送方法
//DH1 = DH(IPK-A私钥, SPK-B公钥)
//DH2 = DH(EPK-A私钥, IPK-B公钥)
//DH3= DH(EPK-A私钥, SPK-B公钥)
//DH4 = DH(IPK-A私钥, OPK--B公钥)
func (p *User) Send(receiver *User) error {
	if receiver == nil {
		return errors.New("用户不存在")
	}
	p.DH1 = XGetCurve25519Key(p.IdentityPri, receiver.SignedPub)
	p.DH2 = XGetCurve25519Key(p.EphemeralPri, receiver.IdentityPub)
	p.DH3 = XGetCurve25519Key(p.EphemeralPri, receiver.SignedPub)
	p.DH4 = XGetCurve25519Key(p.EphemeralPri, receiver.OneTimePub)
	p.ConsultKey = bytes.Join([][]byte{p.DH1[:], p.DH2[:], p.DH3[:], p.DH4[:]}, []byte{})
	return nil
}

// Receiver 初始化接收方法
// DH1 = DH (IPK-A 私钥，SPK-B 公钥)
// DH2 = DH (EPK-A 私钥，IPK-B 公钥)
// DH3= DH (EPK-A 私钥，SPK-B 公钥)
// DH4 = DH (IPK-A 私钥，OPK-B 公钥)
func (p *User) Receiver(sender *User) error {
	if sender == nil {
		return errors.New("用户不存在")
	}
	p.DH1 = XGetCurve25519Key(p.SignedPri, sender.IdentityPub)
	p.DH2 = XGetCurve25519Key(p.IdentityPri, sender.EphemeralPub)
	p.DH3 = XGetCurve25519Key(p.SignedPri, sender.EphemeralPub)
	p.DH4 = XGetCurve25519Key(p.OneTimePri, sender.EphemeralPub)

	p.ConsultKey = bytes.Join([][]byte{p.DH1[:], p.DH2[:], p.DH3[:], p.DH4[:]}, []byte{})
	return nil
}

// Get3Pk 1. 获取对方用户的 IPK、SPK、OPK。
func GetUser(userId string) (user *User) {
	if info, ok := userInfo[userId]; ok {
		user = info
	}
	return
}

// GentEpk 2. 生成自己的临时密钥  EPK（用于后续的棘轮算法）
func GentEpk(user *User) error {
	if user == nil {
		return errors.New("用户不存在")
	}
	user.EphemeralPri, user.EphemeralPub = XGetCurve25519KeypPair()
	return nil
}

// GentX3DH 3. 生成 X3DH 密钥

// GentAD 获取消息加密key
func GentAD(user *User, userid string) (ad []byte) {
	if user == nil {
		return
	}

	if user.MsgRoot == nil {
		user.MsgRoot = make(map[string][32]byte)
		fmt.Println("root 是空的")
	}

	key := SaltKDF(user.ConsultKey, user.MsgRoot[userid])
	input := key[:32]
	//fmt.Println("input:", base64.StdEncoding.EncodeToString(input[:]))
	b2arr32 := func(b []byte) [32]byte {
		a := [32]byte{}
		for i, d := range b {
			a[i] = d
		}
		return a
	}

	user.MsgRoot[userid] = b2arr32(input)
	//root := user.MsgRoot[userid]
	//fmt.Println(userid+"-root-2:", base64.StdEncoding.EncodeToString(root[:]))
	ad = key[32:]
	return
}

// KDF 普通KDF 计算
func KDF(data []byte) [32]byte {
	// create reader
	r := hkdf.New(
		func() hash.Hash {
			return sha256.New()
		},
		data,
		make([]byte, 32), []byte("1"),
	)
	var secret [32]byte
	_, err := r.Read(secret[:])
	if err != nil {
		panic(err)
	}
	return secret
}

// SaltKDF 加盐KDF
func SaltKDF(data []byte, salt [32]byte) [64]byte {
	r := hkdf.New(
		func() hash.Hash {
			return sha256.New()
		},
		data,
		salt[:], nil,
	)
	var secret [64]byte
	_, err := r.Read(secret[:])
	if err != nil {
		panic(err)
	}
	return secret
}

var commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

// EncryptedMsg 4. 用消息密钥S  加密消息
func EncryptedMsg(sender *User, ad []byte, msg string) Message {
	// 创建加密算法 aes
	c, err := aes.NewCipher(ad)
	if err != nil {
		fmt.Printf("Error: NewCipher(%d bytes) = %s", len(ad), err)
		os.Exit(-1)
	}

	// 加密字符串
	cfb := cipher.NewCFBEncrypter(c, commonIV)
	ciphertext := make([]byte, len([]byte(msg)))
	cfb.XORKeyStream(ciphertext, []byte(msg))
	fmt.Printf("%s=>%x\n", []byte(msg), ciphertext)

	return Message{
		Msg:              ciphertext,
		UserIdentityPub:  sender.IdentityPub,
		UserEphemeralPub: sender.EphemeralPub,
		Head:             ad,
	}
}

// ====================================

// 接收消息

// GetMsgKey 1.计算消息密钥 s

// DecryptMsg 2. 解密消息
func DecryptMsg(ad []byte, msg []byte) string {
	// 创建加密算法 aes
	c, err := aes.NewCipher(ad)
	if err != nil {
		fmt.Printf("Error: NewCipher(%d bytes) = %s", len(ad), err)
		os.Exit(-1)
	}
	// 解密字符串
	cfbdec := cipher.NewCFBDecrypter(c, commonIV)
	plaintextCopy := make([]byte, len(msg))
	cfbdec.XORKeyStream(plaintextCopy, msg)
	fmt.Printf("%x=>%s\n", msg, plaintextCopy)

	return ""
}

func XGetCurve25519KeypPair() (Aprivate, Apublic [32]byte) {
	//产生随机数
	if _, err := io.ReadFull(rand.Reader, Aprivate[:]); err != nil {
		os.Exit(0)
	}
	curve25519.ScalarBaseMult(&Apublic, &Aprivate)
	return
}

func XGetCurve25519Key(private, public [32]byte) (Key [32]byte) {
	//产生随机数
	curve25519.ScalarMult(&Key, &private, &public)
	return
}

func TestSend(userA, userB *User, msg chan Message) {
	if userA == nil {
		userA = GetUser("user_1")
	}
	if userB == nil {
		userB = GetUser("user_2")
	}

	fmt.Println(userA.UserID + " 发送消息给 userB" + userB.UserID)

	err := GentEpk(userA) // userA 生成 EPK
	if err != nil {
		return
	}

	err = userA.Send(userB) // userA 初始化发送链
	if err != nil {
		return
	}

	AD := GentAD(userA, userB.UserID) // userA 获取消息密钥
	fmt.Println(userA.UserID+" 获取消息密钥:", base64.StdEncoding.EncodeToString(AD))

	msg <- EncryptedMsg(userA, AD, "w我是 "+userA.UserID+" 我发送的消息，哈哈")
}

func TestReceiver(userA, userB *User, msg chan Message) {
	if userA == nil {
		userA = GetUser("user_1")
	}
	if userB == nil {
		userB = GetUser("user_2")
	}
	message := <-msg

	fmt.Println(userB.UserID + " 接收消息来自 " + userA.UserID)
	userA.EphemeralPub = message.UserEphemeralPub
	userA.IdentityPub = message.UserIdentityPub

	err := GentEpk(userB) // userB 生成 EPK
	if err != nil {
		return
	}

	err = userB.Receiver(userA) // userB 初始化发送链
	if err != nil {
		return
	}

	AD := GentAD(userB, userA.UserID) // userB 获取消息密钥

	fmt.Println(userB.UserID+" 获取消息密钥:", base64.StdEncoding.EncodeToString(AD))

	DecryptMsg(AD, message.Msg)

}

func main() {
	//Test_x3curve25519()
	//msg := make(chan Message, 1)
	//for i := 1; i <= 3; i++ {
	//	switch i {
	//	case 1:
	//		TestSend(nil, nil, msg)
	//		TestReceiver(nil, nil, msg)
	//	case 2:
	//		TestSend(GetUser("user_2"), GetUser("user_1"), msg)
	//		TestReceiver(GetUser("user_2"), GetUser("user_1"), msg)
	//	case 3:
	//		TestSend(GetUser("user_2"), GetUser("user_1"), msg)
	//		TestReceiver(GetUser("user_2"), GetUser("user_1"), msg)
	//	}
	//
	//	fmt.Println("第", i, "次--end", "\n")
	//}

	group := NewGroup(GetUser("user_1"))
	group.Join(GetUser("user_2"))
	group.Join(GetUser("user_3"))
	group.Join(GetUser("user_4"))

	time.Sleep(3 * time.Second)
	group.SendMsg(GetUser("user_4"), "我是用户4，我发送一条群消息")
	time.Sleep(2 * time.Second)
	fmt.Println("------------------  \n")
	group.SendMsg(GetUser("user_2"), "我是用户2，我发送一条群消息")
	fmt.Println("------------------  \n")

	time.Sleep(3 * time.Second)
	group.SendMsg(GetUser("user_4"), "我是用户4，222我发送一条群消息")

	fmt.Println("------------------  \n")
	time.Sleep(2 * time.Second)
	group.Leave(GetUser("user_2"))
	fmt.Println("----------user_2 退出--------  \n")
	time.Sleep(3 * time.Second)
	group.SendMsg(GetUser("user_4"), "我是用户4，222我发送一条群消息")

	time.Sleep(20 * time.Second)

}
