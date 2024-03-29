package main

import (
    "net"
    "os"
    "runtime/debug"
    "regexp"
    "strings"
    "flag"
    "log"
    "fmt"
)
import "github.com/miekg/dns"
//import "github.com/adob/dnsserv"

var ip_regexp = regexp.MustCompile(
    `^(?:[a-z0-9-]+\.)*`+
    `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`+
    `(?:\.[a-z0-9-]+)*\.ip$`)

var redirect_regexp = regexp.MustCompile(
    `^((?:[a-z0-9-]+\.)+)`+
    `goto(?:-[a-z0-9-]+)?$`)

var localhost_regexp = regexp.MustCompile(
    `^(?:[a-z0-9-]+\.)*`+
    `localhost(?:-[a-z0-9-]+)?$`)

var rebindSet_regexp = regexp.MustCompile(
    `^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.([0-9a-f]{40})\.switch$`)

var rebindGet_regexp = regexp.MustCompile(
    `^([0-9a-f]{40})\.switch$`)


var ourDomain string
var ourIPString = ""
var ourIP net.IP
var defaultTTL uint = 1800
var bindAddr string = "0.0.0.0:domain"
var txtMsg = ""

var rebinder = NewRebinder()

func main() {
    flag.StringVar(&ourDomain, "domain", ourDomain, "domain, e.g. adobkin.name to answer for")
    flag.StringVar(&ourIPString, "ip", ourIPString, "IP to resolve to")
    flag.UintVar(&defaultTTL, "ttl", defaultTTL, "default ttl")
    flag.StringVar(&bindAddr, "addr", bindAddr, "interface and port to bind to")
    flag.StringVar(&txtMsg, "txt", txtMsg, "String to in include in TXT records")
    flag.Parse()
    
    checkRequiredArgs("domain", "ip")
    
    if !strings.HasSuffix(ourDomain, ".") {
        ourDomain += "."
    }
    
    if flag.NArg() != 0 {
        fmt.Fprintf(os.Stderr, "too many args provided\n")
        flag.PrintDefaults()
        os.Exit(1)
    }
    
    ourIP = net.ParseIP(ourIPString)
    if ourIP == nil {
        fmt.Fprintf(os.Stderr, "Could not parse IP: %q\n", ourIPString)
        os.Exit(1)
    }
    
    log.Printf("started")
    err := dns.ListenAndServe(bindAddr, "udp", dns.HandlerFunc(serveDNS))
    if err != nil {
        log.Fatalf("error while starting server: %s\n", err.Error())
        os.Exit(1)
    }
}

func checkRequiredArgs(args ...string) {
    for _, arg := range args {
        if flag.Lookup(arg).Value.String() == "" {
            fmt.Fprintf(os.Stderr, "%s required but not specified\n", arg)
            flag.PrintDefaults()
            os.Exit(1)
        }
    }
}

func serveDNS(w dns.ResponseWriter, reqmsg *dns.Msg) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf( 
                    "Panicked while serving DNS response.\n" +
                    "  cause: %s\n\n  == stack ==\n%s\n", r, debug.Stack())
        }
    }()

    if len(reqmsg.Question) != 1 {
        sendErrorReply(w, dns.RcodeServerFailure, "?", reqmsg) // SERVFAIL
    } else {
        domain := strings.ToLower(reqmsg.Question[0].Name)
        qtype := reqmsg.Question[0].Qtype
        sendReply(w, qtype, domain, reqmsg)
    }
}

func sendReply(w dns.ResponseWriter, qtype uint16, question string, reqmsg *dns.Msg) {
    if qtype == dns.TypeTXT {
        sendTXTReply(w, question, reqmsg)
    } else if question == ourDomain {
        sendAReply(w, ourIP, question, defaultTTL, reqmsg)
    } else if !strings.HasSuffix(question, "." + ourDomain) {
        sendErrorReply(w, dns.RcodeServerFailure, question, reqmsg)
    } else if qtype != dns.TypeA {
        sendEmptyReply(w, reqmsg)
    } else {
        prefix := question[0:len(question)-len(ourDomain)-1]
    
        if matches := ip_regexp.FindStringSubmatch(prefix); matches != nil {
            ip := net.ParseIP(matches[1])
            if ip != nil {
                sendAReply(w, ip, question, defaultTTL, reqmsg)
            } else {
                sendErrorReply(w, dns.RcodeNameError, question, reqmsg)
            }
        } else if localhost_regexp.MatchString(prefix) {
            sendAReply(w, net.IP{127,0,0,1}, question, defaultTTL, reqmsg)
        } else if matches := redirect_regexp.FindStringSubmatch(prefix); matches != nil {
            sendCNameReply(w, matches[1], question, reqmsg)
        } else if matches := rebindGet_regexp.FindStringSubmatch(prefix); matches != nil{
            key := matches[1]
            ip := rebinder.Get(key)
            log.Printf("rebind get key=%q ip=%q\n", key, ip)
            if ip != nil {
                sendAReply(w, ip, question, 0, reqmsg)
            } else {
                sendErrorReply(w, dns.RcodeNameError, question, reqmsg)
            }
            
        } else if matches := rebindSet_regexp.FindStringSubmatch(prefix); matches != nil {
            ip := matches[1]
            key := matches[2]
            log.Printf("rebind set key=%q ip=%q\n", key, ip)
            rebinder.SetCmd(key, ip)
            sendErrorReply(w, dns.RcodeNameError, question, reqmsg)
        } else if strings.HasPrefix(prefix, "html") {
            sendCNameReply(w, "<foo>.util.adobkin.name.", question, reqmsg)
	} else {
            sendAReply(w, ourIP, question, defaultTTL, reqmsg)
        }
    }
}

func sendErrorReply(w dns.ResponseWriter, code int, question string, reqmsg *dns.Msg) {
    respmsg := new(dns.Msg)
    respmsg.SetRcode(reqmsg, code)
    
    log.Printf("sending error record to %s for question %s\n", w.RemoteAddr().String(), question)
    sendMsg(w, respmsg)
}

func sendEmptyReply(w dns.ResponseWriter, reqmsg *dns.Msg) {
    respmsg := &dns.Msg{
        Compress: true,
    }
    respmsg.SetReply(reqmsg)
    log.Printf("sending empty record to %s\n", w.RemoteAddr().String())
    sendMsg(w, respmsg)
}
    
func sendAReply(w dns.ResponseWriter, ip net.IP, question string, ttl uint, reqmsg *dns.Msg) {
    respmsg := &dns.Msg{
        Compress: true,
    }
    respmsg.SetReply(reqmsg)
    
    a_rec := &dns.A{
        Hdr: dns.RR_Header{
            Name:   question,
            Rrtype: dns.TypeA,
            Class:  dns.ClassINET,
            Ttl:    uint32(ttl),
        },
        A:  ip,
    }
    
    respmsg.Answer = []dns.RR{a_rec}
    log.Printf("sending A record to %s: question=%q answer=%q id=%d ttl=%d\n", w.RemoteAddr().String(), question, ip.String(), reqmsg.Id, ttl)
    sendMsg(w, respmsg)
}

func sendCNameReply(w dns.ResponseWriter, cname string, question string, reqmsg *dns.Msg) {
    respmsg := &dns.Msg{
        Compress: true,
    }
    respmsg.SetReply(reqmsg)
    
    a_rec := &dns.CNAME{
        Hdr: dns.RR_Header{
            Name:   question,
            Rrtype: dns.TypeCNAME,
            Class:  dns.ClassINET,
            Ttl:    uint32(defaultTTL),
        },
        Target:  cname,
    }
    
    respmsg.Answer = []dns.RR{a_rec}
    
    log.Printf("sending CNAME record to %s: question=%q answer=%q id=%d\n", w.RemoteAddr().String(), question, cname, reqmsg.Id)
    sendMsg(w, respmsg)
}

func sendTXTReply(w dns.ResponseWriter, question string, reqmsg *dns.Msg) {
    respmsg := &dns.Msg{
        Compress: true,
    }
    respmsg.SetReply(reqmsg)

    txt_rec := &dns.TXT{
        Hdr: dns.RR_Header{
            Name: question,
            Rrtype: dns.TypeTXT,
            Class:  dns.ClassINET,
            Ttl:    uint32(defaultTTL),
        },
        Txt: []string{txtMsg},
    }

    respmsg.Answer = []dns.RR{txt_rec}

    log.Printf("sending TXT record to %s: id=%d\n", w.RemoteAddr().String(), reqmsg.Id)
    sendMsg(w, respmsg)
}

func sendMsg(w dns.ResponseWriter, msg *dns.Msg) {
    err := w.WriteMsg(msg)
    if err != nil {
        log.Printf("error while replying to DNS request: %s\n", err.Error())
    }
}
