package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/mkideal/cli"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/flier/opensdp/pkg/endpoint"
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

		endpointLogger := rootLogger.Named("endpoint")

		for _, uri := range opts.Endpoints {
			endpointURI, err := url.Parse(uri)

			if err != nil {
				return fmt.Errorf("fail to parse endpoint URI %s, %v", uri, err)
			}

			endpoint, err := endpoint.ForURI(endpointURI, endpoint.WithLogger(endpointLogger))

			if err != nil {
				return fmt.Errorf("fail to create %s endpoint, %v", endpointURI.Scheme, err)
			}

			go func() error {
				defer wg.Done()
				defer endpoint.Close()

				endpointLogger = endpointLogger.Named(endpoint.Name())

				endpointLogger.Info("endpoint started")

				err := endpoint.Serve(ctx)

				if err != context.Canceled {
					endpointLogger.Error("endpoint was crashed", zap.Error(err))

					cancel()
				} else {
					endpointLogger.Info("endpoint was stopped")
				}

				return err
			}()

			wg.Add(1)
		}

		sigs := make(chan os.Signal, 1)

		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)

		go func() error {
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
		}()

		return
	})
}
