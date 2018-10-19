package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/flier/opensdp/pkg/proxy"

	"github.com/mkideal/cli"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Opts struct {
	cli.Helper

	Debug     bool     `cli:"d, debug" usage:"Debug Output"`
	Verbose   bool     `cli:"v, verbose" usage:"Verbose Output"`
	Endpoints []string `cli:"*e, endpoint" name:"URI" usage:"Endpoint URI"`
}

// Validate check the command line options
func (opts *Opts) Validate(ctx *cli.Context) error {
	return nil
}

func (opts *Opts) initLogger() (logger *zap.Logger, err error) {
	if opts.Debug {
		logger, err = zap.NewDevelopment()
	} else if opts.Verbose {
		logger, err = zap.NewProduction()
	} else {
		cfg := zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
		logger, err = cfg.Build()
	}

	return
}

var rootLogger *zap.Logger

func main() {
	cli.Run(new(Opts), func(cliCtx *cli.Context) (err error) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		opts := cliCtx.Argv().(*Opts)

		if rootLogger, err = opts.initLogger(); err != nil {
			panic(fmt.Sprintf("fail to initial logger, %v", err))
		} else {
			defer rootLogger.Sync()
		}

		logger := rootLogger.Named("main")
		defer logger.Sync()

		logger.Debug("parsed command line", zap.Reflect("opts", opts))

		wg := new(sync.WaitGroup)
		defer wg.Wait()

		for _, endpoint := range opts.Endpoints {
			uri, err := url.Parse(endpoint)

			if err != nil {
				return fmt.Errorf("fail to parse endpoint, %v", err)
			}

			switch uri.Scheme {
			case "socks":
				socksLogger := rootLogger.Named("socks")
				socksServer, err := proxy.NewSocksServer(uri.Host, proxy.WithLogger(socksLogger))

				if err != nil {
					return fmt.Errorf("fail to create socks server, %v", err)
				}

				go func() {
					defer wg.Done()
					defer socksServer.Close()

					socksLogger.Info("socks server started")

					if err := socksServer.Serve(ctx); err != context.Canceled {
						socksLogger.Error("socks server crashed", zap.Error(err))

						cancel()
					} else {
						socksLogger.Info("socks server stopped")
					}
				}()

				wg.Add(1)
			case "http":
			default:
				return fmt.Errorf("unknown proxy scheme: %s", uri.Scheme)
			}
		}

		sigs := make(chan os.Signal, 1)

		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case sig := <-sigs:
				logger.Debug("signal received", zap.Stringer("signal", sig))

				switch sig {
				case os.Interrupt, syscall.SIGTERM:
					logger.Info("stop program", zap.Stringer("reason", sig))

					cancel()

					return nil

				case syscall.SIGUSR1:
					break

				case syscall.SIGUSR2:
					break
				}
			}
		}

		return
	})
}
