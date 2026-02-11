package safebrowsing

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/google/safebrowsing"
	"github.com/sirupsen/logrus"
)



func InspectNameSafeBrowsing(request *model.Request, safebrowser *safebrowsing.SafeBrowser, logger *logrus.Entry) bool {

	for _, request := range request.Req.Question {
		hostname := util.ExtractDomain(request)

		switch safebrowser { //TODO: race condition??
		case nil:
			logger.Info("Safe browsing will be skipped since it is disabled")
			return false
		default:
			url := []string{hostname}
			sbResponse, err := safebrowser.LookupURLs(url)
			if err != nil {
			logger.Warn("Error occured during safe browsing lookup:" + err.Error() + "trying to continue but response may be stale or incomplete.")
			}
			if len(sbResponse[0]) > 0 {
			logger.Warn("Hostname has been found on a safe browsing threat list!", sbResponse[0])
			logger.Warn("Querry will be blocked.")
			return true
			} else {
				logger.Info("Hostname was not found on any threatlists")
				return false
			}
		}
	}
	logger.Error("We should not be able to get here!")
	return false
}



func InspectNameSafeBrowsingString(hostname string, safebrowser *safebrowsing.SafeBrowser, logger *logrus.Entry) bool {

	switch safebrowser { //TODO: race condition??
	case nil:
		logger.Info("Safe browsing will be skipped since it is disabled")
		return false
	default:
		url := []string{hostname}
		sbResponse, err := safebrowser.LookupURLs(url)
		if err != nil {
		logger.Warn("Error occured during safe browsing lookup:" + err.Error() + "trying to continue but response may be stale or incomplete.")
		}
		if len(sbResponse[0]) > 0 {
		logger.Warn("Hostname has been found on a safe browsing threat list!", sbResponse[0])
		logger.Warn("Querry will be blocked.")
		return true
		} else {
			logger.Info("Hostname was not found on any threatlists")
			return false
		}
	}
}




func GetSafeBrowsingConfig() safebrowsing.Config {

	safeBrowsingConfig := safebrowsing.Config {
		APIKey:   "AIzaSyAQTY2mDsHl__G4BrjZwXJzrTMKuIV3SzY",
		DBPath:  getSafeBrowsingDatabasePath(),
		ID:   "scamjam-dns",
		Version:   "1.0",
		Logger:   os.Stdout,
  }

	cfg, err := config.LoadConfig("./config.yml", false) //TODO: path to config should not be hard coded for safe browsing
	if err != nil {
		fmt.Println("Error loading config for SafeBrowsing! SafeBrowsing will not be enabled")
		safeBrowsingConfig.Enabled = false
		return safeBrowsingConfig
	}

	switch cfg.Blocking.SafeBrowsing {
	case true:
		fmt.Println("SafeBrowsing is enabled")
		safeBrowsingConfig.Enabled = true
	case false: 
		fmt.Println("SafeBrowsing is disabled")
		safeBrowsingConfig.Enabled = false
	}
	return safeBrowsingConfig
}


func getSafeBrowsingDatabasePath() string {
	executable, err := os.Executable()
	if err != nil { 
		fmt.Println("Could not find executable root path! Safe browsing will run from non-persistant memory" + err.Error())
		return ""
	} 
	
	safeBrowsingDatabasePath := filepath.Dir(executable) + "\\sb-database"  //TODO: Allow setting sb-database path from config

	return safeBrowsingDatabasePath

}
