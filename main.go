package main

import (
	"encoding/base64"
	"flag"
	"github.com/oxtoacart/bpool"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

type Proxy struct {
	bufPool    *bpool.BytePool
	addr       string
	port       string
	auth       string
	credential string
	debug      bool
}

func main() {
	addr := flag.String("addr", "0.0.0.0", "监听地址， 默认 0.0.0.0")
	port := flag.String("port", "8998", "监听端口， 默认 8888")
	auth := flag.String("auth", "", "验证")
	debug := flag.Bool("debug", false, "开启调试模式")
	flag.Parse()

	// 初始化
	proxy := &Proxy{
		bufPool: bpool.NewBytePool(1024*1024, 32*1024),
		addr:    *addr,
		port:    *port,
		auth:    *auth,
		debug:   *debug,
	}

	// 验证
	if len(*auth) > 0 {
		proxy.Debug("setting need auth: %s", proxy.auth)
		proxy.credential = base64.StdEncoding.EncodeToString([]byte(proxy.auth))
	}

	// 监听端口
	listen := proxy.addr + ":" + proxy.port
	proxy.Printf("go proxy running in %s", listen)
	if err := http.ListenAndServe(listen, proxy); err != nil {
		proxy.Printf("ListenAndServe err %v", err)
	}
}

// 运行代理
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 不是代理流量
	if len(r.URL.Host) == 0 {
		listen := p.addr + ":" + p.port
		if len(p.auth) > 0 {
			listen = p.auth + "@" + listen
		}
		_, _ = w.Write([]byte(listen))
		return
	}

	p.Debug("received request %s %s %s\n", r.Method, r.Host, r.RemoteAddr)

	if !p.handleProxyAuth(w, r) {
		return
	}

	if r.Method != "CONNECT" {
		p.HTTP(w, r)
	} else {
		p.HTTPs(w, r)
	}
}

// 检查客户端提供的验证信息
func (p *Proxy) proxyAuthCheck(r *http.Request) (ok bool) {
	if p.credential == "" {
		return true
	}
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return
	}
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	credential := auth[len(prefix):]
	return credential == p.credential
}

// 告诉客户端需要验证
func (p *Proxy) handleProxyAuth(w http.ResponseWriter, r *http.Request) bool {
	if p.proxyAuthCheck(r) {
		return true
	}
	w.Header().Add("Proxy-Authenticate", "Basic realm=\"*\"")
	w.WriteHeader(http.StatusProxyAuthRequired)
	_, _ = w.Write(nil)
	return false
}

// HTTP
func (p *Proxy) HTTP(w http.ResponseWriter, r *http.Request) {
	transport := http.DefaultTransport
	res, err := transport.RoundTrip(r)
	if err != nil {
		p.Printf("request forward err %v", err)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	// 原样返回 http 头
	for key, value := range res.Header {
		for _, v := range value {
			w.Header().Add(key, v)
		}
	}

	// 原样返回 status code
	w.WriteHeader(res.StatusCode)

	// 返回 body
	n, err := p.Copy(w, res.Body)
	p.Debug("forward length %d, err: %v", n, err)
	_ = res.Body.Close()
}

// HTTPs 隧道代理
func (p *Proxy) HTTPs(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Host
	hij, ok := w.(http.Hijacker)
	if !ok {
		p.Printf("hijack err")
		return
	}

	client, _, err := hij.Hijack()
	if err != nil {
		p.Printf("hijack err %v", err)
		return
	}

	// 建立和服务器的 tcp 连接
	server, err := net.Dial("tcp", addr)
	if err != nil {
		p.Printf("Request forward err %v", err)
		return
	}

	// 告诉客户端连接已经成功建立
	_, _ = client.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))

	// 双向数据转发
	go func(dst io.Writer, src io.Reader) {
		n, err := p.Copy(server, client)
		p.Debug("forward length %d from server to client, err: %v", n, err)
	}(server, client)

	go func(dst io.Writer, src io.Reader) {
		n, err := p.Copy(client, server)
		p.Debug("forward length %d from client to server, err: %v", n, err)
	}(server, client)
}

// buffer 池复制
func (p *Proxy) Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}

	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}

	buf := p.bufPool.Get()
	defer p.bufPool.Put(buf)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}

// log.Printf
func (p *Proxy) Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

// log.Printf 判断 debug 参数
func (p *Proxy) Debug(format string, v ...interface{}) {
	if !p.debug {
		return
	}
	log.Printf(format, v...)
}
