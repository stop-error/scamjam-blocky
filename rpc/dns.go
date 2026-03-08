package rpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/0xERR0R/blocky/log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/billgraziano/dpapi"
	pbalerts "github.com/stop-error/scamjam-service/alerts_proto"
)

var logger = log.Log()
var DnsAlertChan = make(chan *pbalerts.DnsAlert, 20)
var ShutdownClientChan = make(chan struct{})


func initDnsAlertsClient()  (pbalerts.DnsAlertServiceClient, error) {

	programData := os.Getenv("ProgramData")
	scamJamProgramDataCerts := programData + "\\ScamJam\\grpc\\dns\\tls"
	caPEMPath := scamJamProgramDataCerts + "\\scamjam-ca.pem"

	caCertPEMBytes, err := os.ReadFile(caPEMPath)
	if err != nil {
		logger.Error("Error loading grpc server root ca (caCertPEMBytes) from disk!", err)
		return nil, err
	}
	caCertPEMBytes, err = dpapi.DecryptBytes(caCertPEMBytes)
	if err != nil {
		logger.Error("Error decrypting grpc server root ca (caCertPEMBytes)!")
		return nil, err
	}

	//logger.Info("Plain text cert: " + string(caCertPEMBytes))

	certPool := x509.NewCertPool()
  if !certPool.AppendCertsFromPEM(caCertPEMBytes) {
  	logger.Fatal("Error decrypting grpc server root ca (caCertPEMBytes)!")
		return nil, err
  }

  // Create the credentials and return it
  tlsConfig := &tls.Config{
  RootCAs:      certPool,
  }

	tlsCreds := credentials.NewTLS(tlsConfig)
	
	const address = "localhost:32470"

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(tlsCreds))
	if err != nil {
		logger.Error("Failed to init connection to grpc server! ", err)
		return nil, err
	}

	dnsAlertsClient := pbalerts.NewDnsAlertServiceClient(conn)

	stream, err := dnsAlertsClient.Dns(context.Background())
	if err != nil {
		logger.Error("Error opening grpc stream! : ", err)
		return nil, err
	}

	ctx := stream.Context()

	go func() {
		for {
			select {
				case <-ctx.Done():
					logger.Error("Stream loop executed ctx.Done case! (Check the context deadline?)")
					return //Error value?
				case <-ShutdownClientChan:
					logger.Info("Shutting down grpc client...")
					if err := stream.CloseSend(); err != nil {
						logger.Error("Failed to stop grpc stream!", err)
					}
					if err := conn.Close(); err != nil {
						logger.Error("Failed to disconnect from grpc server!", err)
					}
				case dnsAlert := <-DnsAlertChan:
					if err := stream.Send(dnsAlert); err != nil {
						logger.Error("Error sending DnsAlert to server!", err)
					}
				logger.Info("Sent DnsAlert to server", dnsAlert.Hostname)
			}
		}
	}()

	return nil, nil

}


func NewDnsAlert(entity string, source string, category string) *pbalerts.DnsAlert {
	alert := &pbalerts.DnsAlert{
		Hostname: entity,
		Source: source,
		Category: category,
	}
	return alert
}































// func GetDnsAlertsClient() *pbalerts.DnsAlertsClient {
// 	logger := log.Log()
// 	InitDnsAlertsClient()
// 	if InitError == true {
// 		logger.Error("Error starting rpc client!")
// 	}
// 	return client
// }


// func ShutdownDnsAlertsConn() {
// 	logger := log.Log()
// 	shutdownOnce.Do(func() {
//         if conn != nil {
//             err := conn.Close()
// 						if err != nil {
//                 logger.Error("Error closing connection to grpc server!", err)
//             }		
// 				}
// 	})
// }

// func InitDnsThreat(client pbalerts.DnsAlertsClient, hostname string, source string, category string ) {

// 	logger := log.Log()

// 	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
//   defer cancel()

//     req := &pbalerts.DnsAlertMessageFromBlocky{
//         Hostname: hostname,
// 				Source: source,
// 				Category: category,
//     }

//     reply, err := client.Dns(ctx, req)
//     if err != nil {
//         logger.Error("Error sending DnsThreat to grpc server!", err.Error())
// 				//return false, err //TODO: is setting ack to false misleading?
//     }

// 		switch reply.Ack {
// 		case false:
// 			logger.Error("Ack from grpc server was false! (Which should not be possible?)")
// 			//return false, nil
// 		default:
// 			logger.Info("Recieved ack from grpc server!")
// 			//return true, nil
// 		}

// }
		
