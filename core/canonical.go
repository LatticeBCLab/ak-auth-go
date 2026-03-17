package core

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type queryPair struct {
	k string
	v string
}

func BuildStringToSign(in CanonicalRequestInput) string {
	headers := in.Headers
	if headers == nil {
		headers = make(http.Header)
	}

	parts := []string{
		strings.ToUpper(strings.TrimSpace(in.Method)),
		headerValue(headers, AcceptHeader),
		headerValue(headers, ContentMD5Header),
		headerValue(headers, ContentTypeHeader),
		headerValue(headers, DateHeader),
	}

	base := strings.Join(parts, "\n") + "\n"
	return base + BuildCanonicalizedHeaders(headers) + BuildCanonicalizedResource(in.Path, in.Query)
}

func BuildCanonicalizedHeaders(headers http.Header) string {
	type hkv struct {
		k string
		v string
	}
	items := make([]hkv, 0)

	for k, vals := range headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		if !strings.HasPrefix(lk, "x-acs-") {
			continue
		}

		normalized := make([]string, 0, len(vals))
		for _, v := range vals {
			normalized = append(normalized, normalizeHeaderValue(v))
		}
		items = append(items, hkv{k: lk, v: strings.Join(normalized, ",")})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].k < items[j].k
	})

	if len(items) == 0 {
		return ""
	}

	var b strings.Builder
	for _, it := range items {
		b.WriteString(it.k)
		b.WriteString(":")
		b.WriteString(it.v)
		b.WriteString("\n")
	}
	return b.String()
}

func BuildCanonicalizedResource(path string, query url.Values) string {
	p := strings.TrimSpace(path)
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	if len(query) == 0 {
		return p
	}

	pairs := make([]queryPair, 0)
	for k, vals := range query {
		if len(vals) == 0 {
			pairs = append(pairs, queryPair{k: rfc3986Encode(k), v: ""})
			continue
		}
		for _, v := range vals {
			pairs = append(pairs, queryPair{k: rfc3986Encode(k), v: rfc3986Encode(v)})
		}
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k == pairs[j].k {
			return pairs[i].v < pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})

	var b strings.Builder
	b.WriteString(p)
	b.WriteString("?")
	for i, pair := range pairs {
		if i > 0 {
			b.WriteString("&")
		}
		b.WriteString(pair.k)
		b.WriteString("=")
		b.WriteString(pair.v)
	}

	return b.String()
}

func headerValue(headers http.Header, key string) string {
	vals := headers.Values(key)
	if len(vals) == 0 {
		return ""
	}
	if len(vals) == 1 {
		return strings.TrimSpace(vals[0])
	}
	normalized := make([]string, 0, len(vals))
	for _, v := range vals {
		normalized = append(normalized, strings.TrimSpace(v))
	}
	return strings.Join(normalized, ",")
}

func normalizeHeaderValue(v string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(v)), " ")
}

func rfc3986Encode(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}
