package azauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
)

type ResponseHolder struct {
	Resp *http.Response
	Err  error
}

func SetHeaders(req *http.Request, headers map[string]string) *http.Request {
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}

func SendRequest(
	url string,
	method string,
	postBody *map[string]interface{},
	headers map[string]string,
	resp chan<- ResponseHolder,
) {
	client := http.Client{}
	var req *http.Request
	var response *http.Response
	var err error

	switch method {
	case http.MethodGet:
		req, err = http.NewRequest(method, url, nil)
	case http.MethodPost:
		pb, _ := json.Marshal(postBody)
		req, err = http.NewRequest(method, url, bytes.NewBuffer(pb))
	default:
		resp <- ResponseHolder{Resp: nil, Err: errors.New("method not supported")}
		return
	}
	if err != nil {
		log.Printf("Error building request to: %s", url)
		resp <- ResponseHolder{Resp: nil, Err: err}
		return
	}

	SetHeaders(req, headers)
	response, err = client.Do(req)
	if err != nil {
		log.Printf("error sending request: %s", err.Error())
		resp <- ResponseHolder{Resp: nil, Err: err}
		return
	}
	if response.StatusCode > 399 {
		respBody, _ := io.ReadAll(response.Body)
		log.Printf("Request to <<%s>> returned <<%d>> Body: %s", url, response.StatusCode, respBody)
		resp <- ResponseHolder{Resp: nil, Err: errors.New("request generated invalid response")}
		return
	}
	log.Printf("Request to <%s> - status code: <%d>", url, response.StatusCode)

	resp <- ResponseHolder{Resp: response, Err: nil}
}

func getZero[T any]() T {
	var retval T
	return retval
}

func ParseToStruct[T any](source interface{}) (T, error) {
	var resp T
	zeroT := getZero[T]()
	byts, err := json.Marshal(source)
	if err != nil {
		return zeroT, err
	}
	err = json.Unmarshal(byts, &resp)
	return resp, err
}
