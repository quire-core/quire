package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	"github.com/quire-core/quire/internal/api"
	"github.com/quire-core/quire/internal/config"
	"github.com/quire-core/quire/internal/store"
)

func main() {

	apiPort := flag.Int("port", 17345, "port for start quire server")

	flag.Parse()

	if err := config.Init(); err != nil {
		log.Fatalf("init config: %v", err)
	}

	if err := config.CheckEnvs(); err != nil {
		log.Fatalf("check envs: %v", err)
	}

	dbPath := filepath.Join(config.GetQuirePath(), "quire.db")

	if err := store.ConnectDB(dbPath); err != nil {
		log.Fatalf("connect database: %v", err)
	}

	defer func() {
		if err := store.CloseDB(); err != nil {
			log.Printf("close database: %v", err)
		}
	}()

	if err := store.CreateTables(); err != nil {
		log.Fatalf("create tables: %v", err)
	}

	apiServer := &http.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", *apiPort),

		Handler: api.APIServer(),
	}

	log.Printf("Api server running on 127.0.0.1:%d", *apiPort)

	if err := apiServer.ListenAndServe(); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}

}
