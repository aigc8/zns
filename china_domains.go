package zns

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

type ChinaDomainChecker struct {
	domainSet   map[string]struct{}
	suffixTrie  *TrieNode
	mutex       sync.RWMutex
}

func NewChinaDomainChecker() *ChinaDomainChecker {
	return &ChinaDomainChecker{
		domainSet:  make(map[string]struct{}),
		suffixTrie: NewTrieNode(),
	}
}

func (c *ChinaDomainChecker) LoadDomainList(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			c.domainSet[domain] = struct{}{}
		}
	}

	return scanner.Err()
}

func (c *ChinaDomainChecker) LoadSuffixList(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for scanner.Scan() {
		suffix := strings.TrimSpace(scanner.Text())
		if suffix != "" && !strings.HasPrefix(suffix, "//") {
			c.suffixTrie.Insert(suffix)
		}
	}

	return scanner.Err()
}

func (c *ChinaDomainChecker) IsChinaDomain(domain string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// 检查完整域名
	if _, ok := c.domainSet[domain]; ok {
		return true
	}

	// 检查域名后缀
	return c.suffixTrie.Search(domain)
}

type TrieNode struct {
	children map[string]*TrieNode
	isEnd    bool
}

func NewTrieNode() *TrieNode {
	return &TrieNode{
		children: make(map[string]*TrieNode),
	}
}

func (t *TrieNode) Insert(domain string) {
	node := t
	parts := strings.Split(domain, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if _, exists := node.children[part]; !exists {
			node.children[part] = NewTrieNode()
		}
		node = node.children[part]
	}
	node.isEnd = true
}

func (t *TrieNode) Search(domain string) bool {
	node := t
	parts := strings.Split(domain, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if child, exists := node.children[part]; exists {
			if child.isEnd {
				return true
			}
			node = child
		} else {
			return false
		}
	}
	return false
}