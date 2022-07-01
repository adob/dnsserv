//package dnsserve
package main

import (
    //. "fmt"
    "sync"
    //"regexp"
    "net"
    "crypto/sha1"
    "encoding/hex"
    "time"
)

type RebindData struct {
    ip net.IP
    expiration time.Time
}

type Rebinder struct {
    mutex sync.RWMutex
    bindmap map[string]*RebindData
}

func NewRebinder() *Rebinder {
    return &Rebinder{
        bindmap: make(map[string]*RebindData),
    }
}

func (rb *Rebinder) Set(key string, data *RebindData) {
    rb.mutex.Lock()
    defer rb.mutex.Unlock()
    rb.bindmap[key] = data
}

func (rb *Rebinder) SetCmd(keyOrig string, ipString string) {
    ip := net.ParseIP(ipString)
    sha1 := sha1.Sum([]byte(keyOrig))
    key := hex.EncodeToString( sha1[:] )
    
    rb.Set(key, &RebindData{
        ip: ip,
        expiration: time.Now().Add(time.Hour * 24),
    })
}

func (rb *Rebinder) Get(key string) net.IP {
    rb.mutex.RLock()
    defer rb.mutex.RUnlock()
    
    data := rb.bindmap[key]
    
    if data != nil {
        return data.ip
    } else {
        return nil
    }
}

