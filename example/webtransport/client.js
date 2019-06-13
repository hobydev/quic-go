
async function run() {
  const ice = new RTCIceTransport();

  let resolveIceConnected = null;
  const iceConnected = new Promise((resolve, reject) => {
    resolveIceConnected = resolve;
  });
  ice.onstatechange = (e) => {
    log(`ICE state changed to ${ice.state}`); 
    document.querySelector("#ice-state").textContent = ice.state;
    
    if (ice.state == "connected") {
      resolveIceConnected();
    }
  }
  // Doing this as soon as possible is a little bit faster
  ice.gather({});

  const quic = new RTCQuicTransport(ice);

  let resolveQuicConnected = null;
  const quicConnected = new Promise((resolve, reject) => {
    resolveQuicConnected = resolve;
  });
  quic.onstatechange = (e => {
    log(`QUIC state changed to ${quic.state}`);
    document.querySelector("#quic-state").textContent = quic.state;

    if (quic.state == "connected") {
      resolveQuicConnected();
    }
  });

  let serverUrl = `/web-transport`;
  if (location.protocol == "file:") {
    serverUrl = "http://127.0.0.1:3030/web-transport"
  }

  const iceUsernameFragment = ice.getLocalParameters().usernameFragment
  const quicPsk = hexEncode(quic.getKey())
  log(`Fetching ${serverUrl} with ICE username fragment '${iceUsernameFragment}' and PSK '${quicPsk}'`);
  let response = null;
  try {
    response = await fetch(serverUrl, {
      method: "POST",
      headers: new Headers({
        'ice-username-fragment': iceUsernameFragment,
        'quic-psk': quicPsk,
      })
    });
    document.querySelector("#signaling-state").textContent = "worked";
  } catch (error) {
    log(error)
    document.querySelector("#signaling-state").textContent = "failed";
    return;
  }

  console.log(response)
  const serverIceHost = response.headers.get("ice-host");
  const serverIcePort = parseInt(response.headers.get("ice-port"));
  // Not needed because of hack below
  // let serverIceUsernameFragment = response.headers.get("ice-username-fragment");
  const serverIcePassword = response.headers.get("ice-password");
  log (`Fetched /web-transport with ICE host:port of ${serverIceHost}:${serverIcePort} and ICE password of ${serverIcePassword}`);

  // Can't do this until we have the serverIcePassword from above
  ice.start({
    // This is a hack to simplify the server code.  It doesn't need to flip the username around.
    usernameFragment: iceUsernameFragment,
    password: serverIcePassword
  });
  // TODO: Make this work (not require SDP)
  // ice.addRemoteCandidate(new RTCIceCandidate({type: "host", ip: "127.0.0.1", protocol: "udp", port: 3737}));
  ice.addRemoteCandidate(new RTCIceCandidate({sdpMid: "", candidate: `candidate:0 0 UDP 0 ${serverIceHost} 3737 typ host`}));

  await iceConnected;
  quic.connect();
  quic.onquicstream = ({stream}) => {
    log(`Got a QUIC stream: ${stream}`); 
  };
}

function log(msg) {
  console.log(msg);
}

function hexEncode(buf) {
  s = ""
  for (b of new Uint8Array(buf)) {
    s += b.toString(16)
  }
  return s
}

