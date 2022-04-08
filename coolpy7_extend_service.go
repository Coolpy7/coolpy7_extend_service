package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"github.com/plgd-dev/go-coap/v2"
	"github.com/plgd-dev/go-coap/v2/message"
	"github.com/plgd-dev/go-coap/v2/message/codes"
	"github.com/plgd-dev/go-coap/v2/mux"
	"gopkg.in/vmihailenco/msgpack.v2"
	"io/ioutil"

	//"github.com/dgrijalva/jwt-go"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var ctoken []byte

//jwt key
//var secretKey = "Coolpy2020"

func main() {
	var (
		addr  = flag.String("l", ":5683", "绑定Host地址")
		token = flag.String("ht", "coolpy7", "内核扩展功能服务token,（必须与客户端配置一致）")
	)

	flag.Parse()

	ctoken = []byte(*token)

	mr := mux.NewRouter()
	mr.Use(tokenAuth)
	//身份验证
	mr.Handle("/auth", mux.HandlerFunc(handleAuth))
	//订阅
	mr.Handle("/sub", mux.HandlerFunc(handleSub))
	//取消订阅
	mr.Handle("/unsub", mux.HandlerFunc(handleUnSub))
	//消息
	mr.Handle("/pub", mux.HandlerFunc(handlePub))
	//客户端离线
	mr.Handle("/term", mux.HandlerFunc(handleTerm))
	go func() {
		if err := coap.ListenAndServe("udp", *addr, mr); err != nil {
			log.Fatal(err)
		}
	}()

	log.Println("coolpy7 extend server on udp port", *addr)

	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for range signalChan {
			log.Println("safe quit")
			cleanupDone <- true
		}
	}()
	<-cleanupDone
}

func response(w mux.ResponseWriter, m *mux.Message, payload []byte) *message.Message {
	res := message.Message{
		Code:    codes.Content,
		Token:   m.Token,
		Context: w.Client().Context(),
		Options: make(message.Options, 0, 16),
		Body:    bytes.NewReader(payload),
	}
	optsBuf := make([]byte, 32)
	opts, _, _ := res.Options.SetContentFormat(optsBuf, message.AppJSON)
	res.Options = opts
	return &res
}

//token难中间件
func tokenAuth(next mux.Handler) mux.Handler {
	return mux.HandlerFunc(func(w mux.ResponseWriter, r *mux.Message) {
		//判断token是否合法， != 0即为非法
		if bytes.Compare(r.Token, ctoken) != 0 {
			msg := make(map[string]interface{})
			msg["ok"] = false
			msg["err"] = "token error"
			payload, _ := json.Marshal(&msg)
			res := response(w, r, payload)
			_ = w.Client().WriteMessage(res)
			return
		}
		//通过后执行进行服务下一层中间件
		next.ServeCOAP(w, r)
	})
}

//用户身份验证处理函数
func handleAuth(w mux.ResponseWriter, m *mux.Message) {
	payLoad, err := ioutil.ReadAll(m.Body)
	if err != nil {
		log.Println(err)
		return
	}
	var msg map[string]interface{}
	err = msgpack.Unmarshal(payLoad, &msg)
	if err != nil {
		log.Println(err)
		return
	}
	if !msg["ok"].(bool) {
		//错误通知
		log.Println("auth", msg)
	} else {
		//请求消息
		if m.IsConfirmable {
			////固定值判断认证登陆信息合法性
			//if msg["cid"].(string) == "system" && msg["username"].(string) == "premissid" && msg["password"].(string) == "testpremissid" {
			//	msg["ok"] = true
			//}

			////jwt token
			//token, err := jwt.Parse(msg["password"].(string), func(token *jwt.Token) (interface{}, error) {
			//	return []byte(secretKey), nil
			//})
			//if err != nil {
			//	msg["ok"] = false
			//}
			//if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			//	log.Println(claims)
			//	msg["ok"] = true
			//} else {
			//	msg["ok"] = false
			//}

			//默认允许所有请求直接允许登陆
			//允许登陆设置为true,反之设置为false
			msg["ok"] = true
			payload, _ := json.Marshal(&msg)
			//回复内核
			res := response(w, m, payload)
			_ = w.Client().WriteMessage(res)
			return
		}
	}
}

//订阅主题处理函数
//每个用户消息推送都会触发此事件
//cid：客户端身份标识clientid, topic:主题，qos: 消息质量
//返回值：无返回指令
func handleSub(w mux.ResponseWriter, m *mux.Message) {
	payLoad, err := ioutil.ReadAll(m.Body)
	if err != nil {
		log.Println(err)
		return
	}
	var inMsg map[string]interface{}
	err = msgpack.Unmarshal(payLoad, &inMsg)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(inMsg)
}

//每个用户消息推送都会触发此事件
//cid：客户端身份标识clientid, topic:主题，qos: 消息质量
//返回值：无返回指令
func handleUnSub(w mux.ResponseWriter, m *mux.Message) {
	payLoad, err := ioutil.ReadAll(m.Body)
	if err != nil {
		log.Println(err)
		return
	}
	var inMsg map[string]interface{}
	err = msgpack.Unmarshal(payLoad, &inMsg)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(inMsg)
}

//消息推送处理函数
//每个用户消息推送都会触发此事件
//cid：客户端身份标识clientid, topic:主题，qos: 消息质量, payload:消息内容
//返回值：无返回指令
func handlePub(w mux.ResponseWriter, m *mux.Message) {
	body, err := ioutil.ReadAll(m.Body)
	if err != nil {
		log.Println(err)
		return
	}
	var inMsg map[string]interface{}
	err = msgpack.Unmarshal(body, &inMsg)
	if err != nil {
		log.Println(err)
		return
	}
	var payLoad map[string]interface{}
	err = json.Unmarshal(inMsg["payload"].([]byte), &payLoad)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(payLoad)
}

//用户断开连接或意外离线处理函数
//cid：客户端身份标识clientid, err:退出原因
func handleTerm(w mux.ResponseWriter, m *mux.Message) {
	payLoad, err := ioutil.ReadAll(m.Body)
	if err != nil {
		log.Println(err)
		return
	}
	var msg map[string]interface{}
	err = msgpack.Unmarshal(payLoad, &msg)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("term", msg)
}
