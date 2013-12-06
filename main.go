package main

import . "fmt"
import (
    "net"
    "os"
    "runtime/debug"
    "regexp"
    "strings"
    "flag"
)
import "github.com/miekg/dns"

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

var rebinder = NewRebinder()

func main() {
    flag.StringVar(&ourDomain, "domain", ourDomain, "domain, e.g. adobkin.name to answer for")
    flag.StringVar(&ourIPString, "ip", ourIPString, "IP to resolve to")
    flag.UintVar(&defaultTTL, "ttl", defaultTTL, "default ttl")
    flag.StringVar(&bindAddr, "addr", bindAddr, "interface and port to bind to")
    flag.Parse()
    
    checkRequiredArgs("domain", "ip")
    
    if !strings.HasSuffix(ourDomain, ".") {
        ourDomain += "."
    }
    
    if flag.NArg() != 0 {
        Fprintf(os.Stderr, "too many args provided\n")
        flag.PrintDefaults()
        os.Exit(1)
    }
    
    ourIP = net.ParseIP(ourIPString)
    if ourIP == nil {
        Fprintf(os.Stderr, "Could not parse IP: %q\n", ourIPString)
        os.Exit(1)
    }
    
    err := dns.ListenAndServe(bindAddr, "udp", dns.HandlerFunc(serveDNS))
    if err != nil {
        Fprintf(os.Stderr, "error while starting server: %s\n", err.Error())
        os.Exit(1)
    }
}

func checkRequiredArgs(args ...string) {
    for _, arg := range args {
        if flag.Lookup(arg).Value.String() == "" {
            Fprintf(os.Stderr, "%s required but not specified\n", arg)
            flag.PrintDefaults()
            os.Exit(1)
        }
    }
}

func serveDNS(w dns.ResponseWriter, reqmsg *dns.Msg) {
    defer func() {
        if r := recover(); r != nil {
            Fprintf(os.Stderr, 
                    "Panicked while serving DNS response.\n" +
                    "  cause: %s\n\n  == stack ==\n%s\n", r, debug.Stack())
        }
    }()

    var respmsg *dns.Msg
    
    if len(reqmsg.Question) != 1 {
        respmsg = makeErrorReply(dns.RcodeServerFailure, reqmsg) // SERVFAIL
    } else {
        domain := strings.ToLower(reqmsg.Question[0].Name)
        qtype := reqmsg.Question[0].Qtype
        respmsg = makeReplyForQuestion(qtype, domain, reqmsg)
    }
    
    err := w.WriteMsg(respmsg)
    if err != nil {
        Fprintf(os.Stderr, "error while replying to DNS request: %s", err.Error())
    }
}

func makeReplyForQuestion(qtype uint16, question string, reqmsg *dns.Msg) *dns.Msg {
    if question == ourDomain {
        return makeAReply(ourIP, question, defaultTTL, reqmsg)
    } else if !strings.HasSuffix(question, "." + ourDomain) {
        return makeErrorReply(dns.RcodeServerFailure, reqmsg)
    }
    
    if qtype != dns.TypeA {
        return makeEmptyReply(reqmsg)
    }
    
    prefix := question[0:len(question)-len(ourDomain)-1]
    
    if matches := ip_regexp.FindStringSubmatch(prefix); matches != nil {
        ip := net.ParseIP(matches[1])
        if ip != nil {
            return makeAReply(ip, question, defaultTTL, reqmsg)
        } else {
            return makeErrorReply(dns.RcodeNameError, reqmsg)
        }
    } else if localhost_regexp.MatchString(prefix) {
        return makeAReply(net.IP{127,0,0,1}, question, defaultTTL, reqmsg)
    } else if matches := redirect_regexp.FindStringSubmatch(prefix); matches != nil {
        return makeCNameReply(matches[1], question, reqmsg)
    } else if matches := rebindGet_regexp.FindStringSubmatch(prefix); matches != nil{
        key := matches[1]
        ip := rebinder.Get(key)
        Printf("rebind get key=%q ip=%q\n", key, ip)
        if ip != nil {
            return makeAReply(ip, question, 0, reqmsg)
        } else {
            return makeErrorReply(dns.RcodeNameError, reqmsg)
        }
        
    } else if matches := rebindSet_regexp.FindStringSubmatch(prefix); matches != nil {
        ip := matches[1]
        key := matches[2]
        Printf("rebind set key=%q ip=%q\n", key, ip)
        rebinder.SetCmd(key, ip)
        return makeErrorReply(dns.RcodeNameError, reqmsg)
    }
    
    return makeAReply(ourIP, question, defaultTTL, reqmsg)
}

func makeErrorReply(code int, reqmsg *dns.Msg) *dns.Msg {
    respmsg := new(dns.Msg)
    respmsg.SetRcode(reqmsg, code)
    return respmsg
}

func makeEmptyReply(reqmsg *dns.Msg) *dns.Msg {
    respmsg := &dns.Msg{
        Compress: true,
    }
    respmsg.SetReply(reqmsg)
    return respmsg
}
    
func makeAReply(ip net.IP, question string, ttl uint, reqmsg *dns.Msg) *dns.Msg {
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
    
    return respmsg
}

func makeCNameReply(cname string, question string, reqmsg *dns.Msg) *dns.Msg {
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
    
    return respmsg
}
