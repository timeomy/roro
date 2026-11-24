package scan

import (
	"strings"
	"unicode"
)

// credentialWords are whole words that mark a setting name as a credential.
var credentialWords = map[string]bool{
	"password": true, "passwords": true, "passwd": true, "pass": true, "passphrase": true,
	"secret": true, "secrets": true, "token": true, "tokens": true, "apikey": true,
	"auth": true, "authorization": true, "bearer": true, "credential": true, "credentials": true,
	"cookie": true, "cookies": true, "session": true,
}

// keyPrefixWords make a bare "key" a credential, as in API_KEY or PRIVATE_KEY.
var keyPrefixWords = map[string]bool{"api": true, "access": true, "private": true, "secret": true, "client": true}

// notCredentialLast are last words that make a setting a number, a place,
// or a name, not a credential: TOKEN_LIMIT, KEY_FILE, SECRET_NAME.
var notCredentialLast = map[string]bool{
	"max": true, "min": true, "limit": true, "count": true, "size": true, "url": true,
	"path": true, "file": true, "ttl": true, "timeout": true, "env": true, "name": true,
	"prompt": true, "id": true, "mode": true, "type": true, "host": true, "port": true, "region": true,
}

// keyWords splits a setting name into lower-case words on _ - . spaces and
// camelCase boundaries: "apiKey" and "API_KEY" both give [api key].
func keyWords(key string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	runes := []rune(key)
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if len(cur) > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return words
}

// isCredentialKey reports whether a setting name contains a whole word that
// names a secret. "BYPASS_CACHE" and "--passthrough" do not.
func isCredentialKey(key string) bool {
	words := keyWords(key)
	for i, w := range words {
		if credentialWords[w] || (w == "key" && i > 0 && keyPrefixWords[words[i-1]]) {
			return true
		}
	}
	return false
}

// namesNotACredential is true for settings that hold a limit, path, name,
// or similar next to a credential word.
func namesNotACredential(key string) bool {
	words := keyWords(key)
	if len(words) == 0 {
		return false
	}
	return notCredentialLast[words[len(words)-1]] || words[0] == "max" || words[0] == "min"
}
