const express = require("express");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");

const app = express();

app.use(cors());
app.use(express.json());
const frontendDist = path.join(
  __dirname,
  "..",
  "frontend",
  "dist"
);

app.use(express.static(frontendDist));

const PORT = process.env.PORT || 3001;

const uploadDir = path.join(__dirname, "uploads");
const outputDir = path.join(__dirname, "outputs");

fs.mkdirSync(uploadDir, { recursive: true });
fs.mkdirSync(outputDir, { recursive: true });

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({
  storage,

  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== ".pcap") {
      return cb(new Error("Only .pcap files are allowed"));
    }

    cb(null, true);
  }
});

app.post("/api/rules", (req, res) => {
  const { type, value } = req.body;

  if (!type || !value) {
    return res.status(400).json({
      error: "Rule type and value are required"
    });
  }

  const rulesPath = path.join(
    __dirname,
    "..",
    "Packet_analyzer-main",
    "blocking_rules.txt"
  );

  const sections = {
    ip: "[BLOCKED_IPS]",
    app: "[BLOCKED_APPS]",
    domain: "[BLOCKED_DOMAINS]",
    port: "[BLOCKED_PORTS]"
  };

  if (!sections[type]) {
    return res.status(400).json({
      error: "Invalid rule type"
    });
  }

  try {
    let rules = {
      "[BLOCKED_IPS]": [],
      "[BLOCKED_APPS]": [],
      "[BLOCKED_DOMAINS]": [],
      "[BLOCKED_PORTS]": []
    };

    if (fs.existsSync(rulesPath)) {
      const content = fs.readFileSync(rulesPath, "utf8");

      let currentSection = null;

      content.split("\n").forEach(line => {
        line = line.trim();

        if (!line) return;

        if (line.startsWith("[") && line.endsWith("]")) {
          currentSection = line;
        } else if (currentSection && rules[currentSection]) {
          rules[currentSection].push(line);
        }
      });
    }

    const section = sections[type];

    if (!rules[section].includes(value)) {
      rules[section].push(value);
    }

    const output = [
      "[BLOCKED_IPS]",
      ...rules["[BLOCKED_IPS]"],
      "",
      "[BLOCKED_APPS]",
      ...rules["[BLOCKED_APPS]"],
      "",
      "[BLOCKED_DOMAINS]",
      ...rules["[BLOCKED_DOMAINS]"],
      "",
      "[BLOCKED_PORTS]",
      ...rules["[BLOCKED_PORTS]"],
      ""
    ].join("\n");

    fs.writeFileSync(rulesPath, output);

    // Update stats.json
    const statsPath = path.join(
      __dirname,
      "..",
"frontend",
"public",
"stats.json"
    );

    let stats = {};

    if (fs.existsSync(statsPath)) {
      stats = JSON.parse(
        fs.readFileSync(statsPath, "utf8")
      );
    }

    stats.rules = {
      blockedIPs: rules["[BLOCKED_IPS]"].length,
      blockedApps: rules["[BLOCKED_APPS]"].length,
      blockedDomains: rules["[BLOCKED_DOMAINS]"].length,
      blockedPorts: rules["[BLOCKED_PORTS]"].length
    };

    fs.writeFileSync(
      statsPath,
      JSON.stringify(stats, null, 2)
    );

    res.json({
      success: true,
      rule: {
        type,
        value
      },
      stats
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Failed to save rule",
      details: error.message
    });
  }
});
// GET all blocking rules
app.get("/api/rules", (req, res) => {
  try {
    const rulesPath = path.join(
      __dirname,
      "..",
      "Packet_analyzer-main",
      "blocking_rules.txt"
    );

    const rules = {
      ip: [],
      app: [],
      domain: [],
      port: []
    };

    if (fs.existsSync(rulesPath)) {
      const lines = fs.readFileSync(rulesPath, "utf8")
        .split("\n")
        .map(line => line.trim());

      let section = "";

      for (const line of lines) {
        if (line === "[BLOCKED_IPS]") {
          section = "ip";
        } else if (line === "[BLOCKED_APPS]") {
          section = "app";
        } else if (line === "[BLOCKED_DOMAINS]") {
          section = "domain";
        } else if (line === "[BLOCKED_PORTS]") {
          section = "port";
        } else if (line && !line.startsWith("[") && section) {
          rules[section].push(line);
        }
      }
    }

    res.json({
      success: true,
      rules
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "Failed to read rules",
      details: error.message
    });
  }
});


// DELETE blocking rule
app.delete("/api/rules", (req, res) => {
  try {
    const { type, value } = req.body;

    if (!type || !value) {
      return res.status(400).json({
        success: false,
        error: "type and value are required"
      });
    }

    const rulesPath = path.join(
      __dirname,
      "..",
      "Packet_analyzer-main",
      "blocking_rules.txt"
    );

    const sectionMap = {
      ip: "[BLOCKED_IPS]",
      app: "[BLOCKED_APPS]",
      domain: "[BLOCKED_DOMAINS]",
      port: "[BLOCKED_PORTS]"
    };

    const targetSection = sectionMap[type];

    if (!targetSection) {
      return res.status(400).json({
        success: false,
        error: "Invalid rule type"
      });
    }

    const sections = {
      "[BLOCKED_IPS]": [],
      "[BLOCKED_APPS]": [],
      "[BLOCKED_DOMAINS]": [],
      "[BLOCKED_PORTS]": []
    };

    let currentSection = null;

    const lines = fs.readFileSync(rulesPath, "utf8")
      .split("\n")
      .map(line => line.trim());

    for (const line of lines) {

      if (sections.hasOwnProperty(line)) {
        currentSection = line;
        continue;
      }

      if (line && currentSection) {
        sections[currentSection].push(line);
      }
    }

    sections[targetSection] = sections[targetSection].filter(
      rule => rule.toLowerCase() !== value.toLowerCase()
    );

    const output = [
      "[BLOCKED_IPS]",
      ...sections["[BLOCKED_IPS]"],
      "",
      "[BLOCKED_APPS]",
      ...sections["[BLOCKED_APPS]"],
      "",
      "[BLOCKED_DOMAINS]",
      ...sections["[BLOCKED_DOMAINS]"],
      "",
      "[BLOCKED_PORTS]",
      ...sections["[BLOCKED_PORTS]"],
      ""
    ].join("\n");

    fs.writeFileSync(rulesPath, output);

    res.json({
      success: true,
      deleted: {
        type,
        value
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "Failed to delete rule",
      details: error.message
    });
  }
});
  app.post("/api/analyze", upload.single("pcap"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      error: "No PCAP file uploaded"
    });
  }

  console.log("\n=================================");
  console.log("UPLOADED FILE:", req.file.originalname);
  console.log("SAVED FILE:", req.file.path);
  console.log("SIZE:", req.file.size);
  console.log("=================================");

  const inputFile = req.file.path;

  const timestamp = Date.now();

  const outputFile = path.join(
    outputDir,
    `${timestamp}-filtered.pcap`
  );

  const statsPath = path.join(
    outputDir,
    `${timestamp}-stats.json`
  );

  const connectionsPath = path.join(
    outputDir,
    `${timestamp}-connections.json`
  );

  const engine = path.join(
    __dirname,
    "..",
    "Packet_analyzer-main",
    "build",
    "dpi_engine"
  );

  console.log("ENGINE:", engine);
  console.log("INPUT:", inputFile);
  console.log("OUTPUT:", outputFile);
  console.log("STATS:", statsPath);
  console.log("CONNECTIONS:", connectionsPath);

  if (!fs.existsSync(engine)) {
    console.error("DPI ENGINE NOT FOUND:", engine);

    return res.status(500).json({
      success: false,
      error: "DPI engine not found",
      details: engine
    });
  }

  if (!fs.existsSync(inputFile)) {
    return res.status(500).json({
      success: false,
      error: "Uploaded PCAP not found",
      details: inputFile
    });
  }

  const engineArgs = [
    inputFile,
    outputFile
  ];

  const rulesPath = path.join(
    __dirname,
    "..",
    "Packet_analyzer-main",
    "blocking_rules.txt"
  );

  if (fs.existsSync(rulesPath)) {
    engineArgs.push("--rules", rulesPath);
  }

  /*
   * Special blocking demo
   */
  if (
    req.file.originalname
      .toLowerCase()
      .includes("blocking-demo")
  ) {
    engineArgs.push(
      "--block-ip",
      "192.168.1.50"
    );
  }

  console.log("ENGINE ARGS:", engineArgs);

  execFile(
    engine,
    engineArgs,
    {
      timeout: 60000,

      cwd: path.join(
        __dirname,
        "..",
        "Packet_analyzer-main"
      ),

      env: {
        ...process.env,

        PACKETHUNTER_STATS_PATH: statsPath,

        PACKETHUNTER_CONNECTIONS_PATH:
          connectionsPath
      },

      maxBuffer: 10 * 1024 * 1024
    },

    (error, stdout, stderr) => {

      console.log("\n========== DPI ENGINE STDOUT ==========");
      console.log(stdout || "(empty)");
      console.log("=======================================\n");

      console.log("\n========== DPI ENGINE STDERR ==========");
      console.log(stderr || "(empty)");
      console.log("=======================================\n");

      if (error) {
        console.error(
          "DPI ENGINE ERROR:",
          error
        );

        return res.status(500).json({
          success: false,
          error: "DPI engine failed",
          details:
            stderr ||
            stdout ||
            error.message
        });
      }

      /*
       * Make sure engine actually produced output.
       */
      if (!fs.existsSync(outputFile)) {
        console.error(
          "Output PCAP was not created:",
          outputFile
        );

        return res.status(500).json({
          success: false,
          error: "DPI engine did not create output PCAP",
          details: stdout
        });
      }

      /*
       * Read generated statistics.
       */
      if (!fs.existsSync(statsPath)) {

        console.error(
          "Statistics file was not generated:",
          statsPath
        );

        return res.status(500).json({
          success: false,
          error: "Statistics file was not generated",
          details:
            "The C++ engine completed, but did not create the expected stats JSON.",
          engineOutput: stdout
        });
      }

      let stats;

      try {

        stats = JSON.parse(
          fs.readFileSync(
            statsPath,
            "utf8"
          )
        );

      } catch (parseError) {

        console.error(
          "Invalid stats JSON:",
          parseError
        );

        return res.status(500).json({
          success: false,
          error: "Invalid statistics JSON",
          details: parseError.message
        });
      }

      /*
       * Read connections.
       */
      let connections = [];

      if (fs.existsSync(connectionsPath)) {

        try {

          const connectionsData =
            JSON.parse(
              fs.readFileSync(
                connectionsPath,
                "utf8"
              )
            );

          connections =
            connectionsData.connections || [];

        } catch (connectionError) {

          console.error(
            "Failed to parse connections:",
            connectionError
          );

        }
      }

      /*
       * Read current blocking rules.
       */
      const rules = {
        blockedIPs: 0,
        blockedApps: 0,
        blockedDomains: 0,
        blockedPorts: 0
      };

      if (fs.existsSync(rulesPath)) {

        const content =
          fs.readFileSync(
            rulesPath,
            "utf8"
          );

        let currentSection = null;

        content
          .split("\n")
          .forEach((line) => {

            line = line.trim();

            if (!line) return;

            if (line === "[BLOCKED_IPS]") {
              currentSection = "ip";
              return;
            }

            if (line === "[BLOCKED_APPS]") {
              currentSection = "app";
              return;
            }

            if (line === "[BLOCKED_DOMAINS]") {
              currentSection = "domain";
              return;
            }

            if (line === "[BLOCKED_PORTS]") {
              currentSection = "port";
              return;
            }

            if (currentSection) {

              if (currentSection === "ip") {
                rules.blockedIPs++;
              }

              if (currentSection === "app") {
                rules.blockedApps++;
              }

              if (currentSection === "domain") {
                rules.blockedDomains++;
              }

              if (currentSection === "port") {
                rules.blockedPorts++;
              }
            }
          });
      }

      stats.rules = rules;

      /*
       * Ensure fields expected by React exist.
       */
      stats = {
        totalPackets: 0,
        totalBytes: 0,
        forwardedPackets: 0,
        droppedPackets: 0,
        tcpPackets: 0,
        udpPackets: 0,
        otherPackets: 0,
        activeConnections: connections.length,

        lbReceived: 0,
        lbDispatched: 0,

        fpProcessed: 0,
        fpForwarded: 0,
        fpDropped: 0,

        applications: {},
        trafficData: [],

        ...stats,

        rules
      };

      /*
       * Save frontend-compatible stats.
       */
      const frontendStatsPath = path.join(
        __dirname,
        "..",
        "frontend",
        "public",
        "stats.json"
      );

      fs.writeFileSync(
        frontendStatsPath,
        JSON.stringify(
          stats,
          null,
          2
        )
      );

      /*
       * Save frontend-compatible connections.
       */
      const frontendConnectionsPath = path.join(
        __dirname,
        "..",
        "frontend",
        "public",
        "connections.json"
      );

      fs.writeFileSync(
        frontendConnectionsPath,
        JSON.stringify(
          {
            connections
          },
          null,
          2
        )
      );

      console.log(
        "\n========== FINAL DPI RESULT =========="
      );

      console.log(
        "Packets:",
        stats.totalPackets
      );

      console.log(
        "TCP:",
        stats.tcpPackets
      );

      console.log(
        "UDP:",
        stats.udpPackets
      );

      console.log(
        "Forwarded:",
        stats.forwardedPackets
      );

      console.log(
        "Dropped:",
        stats.droppedPackets
      );

      console.log(
        "Connections:",
        connections.length
      );

      console.log(
        "Applications:",
        stats.applications
      );

      console.log(
        "======================================\n"
      );

      return res.json({
        success: true,

        stats,

        connections,

        outputFile:
          path.basename(outputFile)
      });
    }
  );
});

app.get("/api/download/:filename", (req, res) => {
  const filename = path.basename(req.params.filename);
  const filePath = path.join(outputDir, filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({
      error: "Output file not found"
    });
  }

  res.download(filePath, filename);
});

app.use((err, req, res, next) => {
  res.status(400).json({
    error: err.message
  });
});
app.use((req, res, next) => {
  if (
    req.method === "GET" &&
    !req.path.startsWith("/api/")
  ) {
    return res.sendFile(
      path.join(frontendDist, "index.html")
    );
  }

  next();
});



app.listen(PORT, "0.0.0.0", () => {
  console.log(`PacketHunter running on port ${PORT}`);
});

