package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/dosco/graphjin/core"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/sessions"
	"github.com/rbcervilla/redisstore/v8"
	"log"
	"net/http"
)

func GorillaHandler(ac Auth) (handlerFunc, error) {
	gu := ac.Gorilla.Type

	if gu == "redis" {
		return GorillaRedisHandler(ac)
	}

	return nil, errors.New("invalid gorilla type")
}

func GorillaRedisHandler(ac Auth) (handlerFunc, error) {
	cookie := ac.Cookie

	if len(cookie) == 0 {
		return nil, fmt.Errorf("no auth.cookie defined")
	}

	if len(ac.Gorilla.Redis.Addr) == 0 {
		return nil, fmt.Errorf("no auth.gorilla.redis.addr defined")
	}

	rdb := redis.NewClient(&redis.Options{
		Network:            ac.Gorilla.Redis.Network,
		Addr:               ac.Gorilla.Redis.Addr,
		Username:           ac.Gorilla.Redis.Username,
		Password:           ac.Gorilla.Redis.Password,
		DB:                 ac.Gorilla.Redis.DB,
		MaxRetries:         ac.Gorilla.Redis.MaxRetries,
		MinRetryBackoff:    ac.Gorilla.Redis.MinRetryBackoff,
		MaxRetryBackoff:    ac.Gorilla.Redis.MaxRetryBackoff,
		DialTimeout:        ac.Gorilla.Redis.DialTimeout,
		ReadTimeout:        ac.Gorilla.Redis.ReadTimeout,
		WriteTimeout:       ac.Gorilla.Redis.WriteTimeout,
		PoolSize:           ac.Gorilla.Redis.PoolSize,
		MinIdleConns:       ac.Gorilla.Redis.MinIdleConns,
		MaxConnAge:         ac.Gorilla.Redis.MaxConnAge,
		PoolTimeout:        ac.Gorilla.Redis.PoolTimeout,
		IdleTimeout:        ac.Gorilla.Redis.IdleTimeout,
		IdleCheckFrequency: ac.Gorilla.Redis.IdleCheckFrequency,
	})

	store, err := redisstore.NewRedisStore(context.Background(), rdb)
	if err != nil {
		log.Fatal("failed to create redis store: ", err)
	}

	store.KeyGen(nil)
	store.KeyPrefix(ac.Gorilla.Store.Prefix)
	store.Options(sessions.Options{
		Path:     ac.Gorilla.SessionOptions.Path,
		Domain:   ac.Gorilla.SessionOptions.Domain,
		MaxAge:   ac.Gorilla.SessionOptions.MaxAge,
		Secure:   ac.Gorilla.SessionOptions.Secure,
		HttpOnly: ac.Gorilla.SessionOptions.HttpOnly,
		SameSite: ac.Gorilla.SessionOptions.SameSite,
	})

	return func(w http.ResponseWriter, r *http.Request) (context.Context, error) {
		session, err := store.New(r, ac.Cookie)
		if err != nil {
			return nil, err401
		}

		var (
			accountUuid string
			ok          bool
		)
		if x, found := session.Values[ac.Gorilla.Store.UserIdKey]; found {
			if accountUuid, ok = x.(string); !ok {
				return nil, err401
			}
		} else {
			return nil, err401
		}

		ctx := context.WithValue(r.Context(), core.UserIDKey, accountUuid)
		return ctx, nil
	}, nil
}
