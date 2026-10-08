// Command heain-files is the file base app: large files (masters, footage,
// audio, scans) stored in chunks, each file under its own data key in
// heain-core's KMS, on the local disk by default or in any S3-compatible
// object store. It is configured through the heain-sdk HEAIN_* variables
// (heain.StartFromEnv) and runs however the operator likes: a plain
// process, a service unit, or a container.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-files/internal/api"
	"github.com/heainframework/heain-files/internal/backend"
	"github.com/heainframework/heain-files/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	kind := flag.String("backend", env("HEAIN_FILES_BACKEND", "disk"), "where chunks go: disk or s3 (env HEAIN_FILES_BACKEND)")
	root := flag.String("disk-root", os.Getenv("HEAIN_FILES_DISK_ROOT"), "disk backend directory (env HEAIN_FILES_DISK_ROOT); default <state>/blobs")
	sweep := flag.Duration("sweep", time.Minute, "how often expired files and abandoned uploads are removed")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	state := env("HEAIN_STATE_DIR", "/state")
	var be backend.Backend
	switch *kind {
	case "disk":
		if *root == "" {
			*root = filepath.Join(state, "blobs")
		}
		be = backend.Disk{Root: *root}
	case "s3":
		// credentials only from the environment, never from flags (ps)
		s3 := backend.S3{Endpoint: os.Getenv("HEAIN_FILES_S3_ENDPOINT"), Region: env("HEAIN_FILES_S3_REGION", "us-east-1"),
			Bucket: os.Getenv("HEAIN_FILES_S3_BUCKET"), Prefix: os.Getenv("HEAIN_FILES_S3_PREFIX"),
			AccessKey: os.Getenv("HEAIN_FILES_S3_ACCESS_KEY"), SecretKey: os.Getenv("HEAIN_FILES_S3_SECRET_KEY")}
		if s3.Endpoint == "" || s3.Bucket == "" || s3.AccessKey == "" || s3.SecretKey == "" {
			log.Fatal("heain-files: -backend s3 needs HEAIN_FILES_S3_ENDPOINT, _BUCKET, _ACCESS_KEY and _SECRET_KEY")
		}
		be = s3
	default:
		log.Fatalf("heain-files: unknown -backend %q (disk or s3)", *kind)
	}

	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	log.Printf("heain-files: registered (%s), waiting for admission", app.Status())
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	inside, err := app.DataKey(ctx, "inside")
	if err != nil {
		log.Fatalf("heain-files: data key from core: %v", err)
	}
	st, err := store.Open(filepath.Join(state, "files.db"), inside, be, store.Keys{Sealer: app.Sealer, Destroy: app.DestroyDataKey})
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	a := &api.API{Store: st, Instance: os.Getenv("HEAIN_INSTANCE"), Logf: log.Printf}
	srv := app.NewServer()
	if err := a.Register(srv); err != nil {
		log.Fatal(err)
	}
	go a.Sweep(ctx, *sweep)
	l, err := net.Listen("tcp", heain.Listen(":19490"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("heain-files: active, serving on %s (backend: %s)", l.Addr(), be.Kind())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
	log.Printf("heain-files: deregistered")
}
