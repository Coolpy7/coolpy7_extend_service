package main

import (
	"bytes"
	"encoding/json"
	"flag"
	//"github.com/dgrijalva/jwt-go"
	"github.com/jacoblai/go-coap"
	"log"
	"net"
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

	mux := coap.NewServeMux()
	//身份验证
	mux.Handle("/auth", tokenAuth(coap.FuncHandler(handleAuth)))
	//订阅
	mux.Handle("/sub", tokenAuth(coap.FuncHandler(handleSub)))
	//取消订阅
	mux.Handle("/unsub", tokenAuth(coap.FuncHandler(handleUnSub)))
	//消息
	mux.Handle("/pub", tokenAuth(coap.FuncHandler(handlePub)))
	//客户端离线
	mux.Handle("/term", tokenAuth(coap.FuncHandler(handleTerm)))

	go func() {
		if err := coap.ListenAndServe("udp", *addr, mux); err != nil {
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

func response(m *coap.Message, payload []byte) *coap.Message {
	res := &coap.Message{
		Type:      coap.Acknowledgement,
		Code:      coap.Content,
		MessageID: m.MessageID,
		Token:     m.Token,
		Payload:   payload,
	}
	res.SetOption(coap.ContentFormat, coap.AppJSON)
	return res
}

//token难中间件
func tokenAuth(next coap.Handler) coap.Handler {
	return coap.FuncHandler(func(l *net.UDPConn, a *net.UDPAddr, m *coap.Message) *coap.Message {
		//判断token是否合法， != 0即为非法
		if bytes.Compare(m.Token, ctoken) != 0 {
			msg := make(map[string]interface{})
			msg["ok"] = false
			msg["err"] = "token error"
			payload, _ := json.Marshal(&msg)
			res := &coap.Message{
				Type:      coap.Acknowledgement,
				Code:      coap.Content,
				MessageID: m.MessageID,
				Token:     m.Token,
				Payload:   payload,
			}
			res.SetOption(coap.ContentFormat, coap.AppJSON)
			return nil
		}
		//通过后执行进行服务下一层中间件
		return next.ServeCOAP(l, a, m)
	})
}

//用户身份验证处理函数
func handleAuth(l *net.UDPConn, a *net.UDPAddr, m *coap.Message) *coap.Message {
	var msg map[string]interface{}
	err := json.Unmarshal(m.Payload, &msg)
	if err != nil {
		log.Println(err)
		return nil
	}
	if !msg["ok"].(bool) {
		//错误通知
		log.Println("auth", msg)
	} else {
		//请求消息
		if m.IsConfirmable() {
			msg := make(map[string]interface{})

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
			return response(m, payload)
		}
	}
	return nil
}

//订阅主题处理函数
//每个用户消息推送都会触发此事件
//cid：客户端身份标识clientid, topic:主题，qos: 消息质量
//返回值：无返回指令
func handleSub(l *net.UDPConn, a *net.UDPAddr, m *coap.Message) *coap.Message {
	var inMsg map[string]interface{}
	err := json.Unmarshal(m.Payload, &inMsg)
	if err != nil {
		log.Println(err)
		return nil
	}
	log.Println(inMsg)
	return nil
}

//每个用户消息推送都会触发此事件
//cid：客户端身份标识clientid, topic:主题，qos: 消息质量
//返回值：无返回指令
func handleUnSub(l *net.UDPConn, a *net.UDPAddr, m *coap.Message) *coap.Message {
	var inMsg map[string]interface{}
	err := json.Unmarshal(m.Payload, &inMsg)
	if err != nil {
		log.Println(err)
		return nil
	}
	log.Println(inMsg)
	return nil
}

//消息推送处理函数
//每个用户消息推送都会触发此事件
//cid：客户端身份标识clientid, topic:主题，qos: 消息质量, payload:消息内容
//返回值：无返回指令
func handlePub(l *net.UDPConn, a *net.UDPAddr, m *coap.Message) *coap.Message {
	var inMsg map[string]interface{}
	err := json.Unmarshal(m.Payload, &inMsg)
	if err != nil {
		log.Println(err)
		return nil
	}
	log.Println(inMsg)
	return nil
}

//用户断开连接或意外离线处理函数
//cid：客户端身份标识clientid, err:退出原因
func handleTerm(l *net.UDPConn, a *net.UDPAddr, m *coap.Message) *coap.Message {
	var msg map[string]interface{}
	err := json.Unmarshal(m.Payload, &msg)
	if err != nil {
		log.Println(err)
		return nil
	}
	log.Println("term", msg)
	return nil
}
