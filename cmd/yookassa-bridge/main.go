package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/artemk1337/kiro-admin/internal/yookassabridge"
)

func main() {
	cfg, err := yookassabridge.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	store, err := yookassabridge.NewStore(cfg.DataFile)
	if err != nil {
		log.Fatal(err)
	}
	server := yookassabridge.NewServer(
		cfg,
		store,
		yookassabridge.NewYooKassaClient(cfg.YooKassaShopID, cfg.YooKassaSecretKey),
		yookassabridge.NewNewAPIClient(cfg.NewAPIBaseURL, cfg.NewAPIAdminToken, cfg.NewAPIAdminUserID),
	)
	server.StartReconciler(context.Background(), 10*time.Second)
	log.Printf("yookassa bridge listens on %s, public URL %s", cfg.ListenAddr, cfg.PublicBaseURL)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, server.Handler()))
}
