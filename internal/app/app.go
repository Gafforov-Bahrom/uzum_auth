package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"sync"

	gateway_runtime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jmoiron/sqlx"
	"github.com/kelseyhightower/envconfig"
	_ "github.com/lib/pq"
	"github.com/mvrilo/go-redoc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Shemistan/uzum_auth/dev"
	"github.com/Shemistan/uzum_auth/docs"
	auth_system_v1 "github.com/Shemistan/uzum_auth/internal/api/auth_v1"
	"github.com/Shemistan/uzum_auth/internal/models"
	auth_system "github.com/Shemistan/uzum_auth/internal/service/auth"
	"github.com/Shemistan/uzum_auth/internal/storage/postgresql"
	pb "github.com/Shemistan/uzum_auth/pkg/auth_v1"
)

type App struct {
	appConfig *models.Config
	mux       *gateway_runtime.ServeMux

	grpcServer        *grpc.Server
	authSystemService auth_system.IAuthSystemService
	reDoc             redoc.Redoc

	db *sqlx.DB
}

func NewApp(ctx context.Context) (*App, error) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	a := &App{}

	a.setConfig()
	a.initDB()
	a.initReDoc()
	a.initGRPCServer()

	if err := a.initHTTPServer(ctx); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *App) Run() error {
	wg := sync.WaitGroup{}
	wg.Add(3)

	go func() {
		defer wg.Done()

		log.Fatal(a.runGRPC())
	}()

	go func() {
		defer wg.Done()
		log.Fatal(a.runHTTP())
	}()

	go func() {
		defer wg.Done()

		log.Fatal(a.runDocumentation())
	}()

	wg.Wait()
	return nil
}

func (a *App) setConfig() {
	if dev.DEBUG {
		err := dev.SetConfig()
		if err != nil {
			log.Fatal("failed to get config:", err.Error())
		}

	}
	conf := models.Config{}

	envconfig.MustProcess("", &conf)

	a.appConfig = &conf
}

func (a *App) initDB() {
	sqlConnectionString := a.getSqlConnectionString()

	var err error
	a.db, err = sqlx.Open("postgres", sqlConnectionString)
	if err != nil {
		log.Fatal("failed to opening connection to db: ", err.Error())
	}

	// Проверка соединения с базой данных
	if err = a.db.Ping(); err != nil {
		log.Fatal("failed to connect to the database: ", err.Error())
	}
}

func (a *App) initGRPCServer() {
	a.grpcServer = grpc.NewServer()
	pb.RegisterAuthV1Server(
		a.grpcServer,
		&auth_system_v1.Auth{
			AuthService: a.getAuthSystemService(),
		},
	)
}

func (a *App) initHTTPServer(ctx context.Context) error {
	a.mux = gateway_runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	err := pb.RegisterAuthV1HandlerFromEndpoint(ctx, a.mux, a.appConfig.App.PortGRPC, opts)
	if err != nil {
		return err
	}

	return nil
}

func (a *App) initReDoc() {
	a.reDoc = docs.Initialize()
}

func (a *App) runGRPC() error {
	listener, err := net.Listen("tcp", a.appConfig.App.PortGRPC)
	if err != nil {
		return err
	}

	log.Println("GRPC server running on port:", a.appConfig.App.PortGRPC)

	return a.grpcServer.Serve(listener)
}

func (a *App) runHTTP() error {
	log.Println("HTTP server is running on port:", a.appConfig.App.PortHTTP)

	return http.ListenAndServe(a.appConfig.App.PortHTTP, a.mux)
}

func (a *App) runDocumentation() error {
	log.Println("Swagger documentation running on port:", a.appConfig.App.PortDocs)

	return http.ListenAndServe(a.appConfig.App.PortDocs, a.reDoc.Handler())
}

func (a *App) getAuthSystemService() auth_system.IAuthSystemService {
	storage := postgresql.NewStorage(a.db)

	if a.authSystemService == nil {
		a.authSystemService = auth_system.NewAuthSystemService(a.appConfig, storage)
	}

	return a.authSystemService
}

func (a *App) getSqlConnectionString() string {
	sqlConnectionString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%v",
		a.appConfig.DB.User,
		a.appConfig.DB.Password,
		a.appConfig.DB.Host,
		a.appConfig.DB.Port,
		a.appConfig.DB.Database,
		a.appConfig.DB.SSLMode,
	)

	return sqlConnectionString
}