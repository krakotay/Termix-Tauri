import type { TunnelConnection } from "@/types";

export interface ParsedSshCommand {
  host: string;
  username?: string;
  port?: number;
  identityFile?: string;
  tunnels: TunnelConnection[];
}

function tokenizeCommand(command: string) {
  const tokens: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let escaping = false;

  for (const char of command.trim()) {
    if (escaping) {
      current += char;
      escaping = false;
      continue;
    }

    if (char === "\\") {
      escaping = true;
      continue;
    }

    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }

    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }

    current += char;
  }

  if (current) {
    tokens.push(current);
  }

  return tokens;
}

function parsePort(value: string | undefined) {
  if (!value || !/^\d+$/.test(value)) {
    return undefined;
  }

  const port = Number(value);
  return port >= 1 && port <= 65535 ? port : undefined;
}

function normalizeTunnelHost(value: string) {
  return value === "localhost" ? "127.0.0.1" : value;
}

function parseDestination(value: string) {
  const normalized = value.startsWith("ssh://") ? value : `ssh://${value}`;

  try {
    const url = new URL(normalized);
    return {
      host: url.hostname,
      username: url.username ? decodeURIComponent(url.username) : undefined,
      port: parsePort(url.port),
    };
  } catch {
    const atIndex = value.lastIndexOf("@");
    const username = atIndex > -1 ? value.slice(0, atIndex) : undefined;
    const hostWithPort = atIndex > -1 ? value.slice(atIndex + 1) : value;
    const bracketMatch = hostWithPort.match(/^\[([^\]]+)\](?::(\d+))?$/);

    if (bracketMatch) {
      return {
        host: bracketMatch[1],
        username,
        port: parsePort(bracketMatch[2]),
      };
    }

    const portMatch = hostWithPort.match(/^([^:]+):(\d+)$/);
    return {
      host: portMatch ? portMatch[1] : hostWithPort,
      username,
      port: parsePort(portMatch?.[2]),
    };
  }
}

function parseForwardSpec(
  mode: "local" | "remote" | "dynamic",
  spec: string,
): TunnelConnection | null {
  const parts = spec.split(":");
  const numericIndex = parts.findIndex((part) => parsePort(part) !== undefined);

  if (numericIndex === -1) {
    return null;
  }

  const bindHost =
    numericIndex > 0
      ? normalizeTunnelHost(parts.slice(0, numericIndex).join(":"))
      : "";
  const sourcePort = parsePort(parts[numericIndex]);
  if (!sourcePort) {
    return null;
  }

  if (mode === "dynamic") {
    return {
      scope: "s2s",
      mode,
      tunnelType: "local",
      bindHost,
      sourcePort,
      endpointPort: 22,
      endpointHost: "",
      targetHost: "",
      maxRetries: 3,
      retryInterval: 10,
      autoStart: false,
    };
  }

  const target = parts.slice(numericIndex + 1);
  const endpointPort = parsePort(target.at(-1));
  if (!endpointPort || target.length < 2) {
    return null;
  }

  const targetHost = normalizeTunnelHost(
    target.slice(0, -1).join(":") || "127.0.0.1",
  );

  return {
    scope: "s2s",
    mode,
    tunnelType: mode === "remote" ? "remote" : "local",
    bindHost: mode === "local" ? bindHost || "127.0.0.1" : "",
    targetHost: mode === "remote" ? targetHost : "",
    sourcePort,
    endpointPort,
    endpointHost: "",
    maxRetries: 3,
    retryInterval: 10,
    autoStart: false,
  };
}

export function parseSshCommand(command: string): ParsedSshCommand | null {
  const tokens = tokenizeCommand(command);
  if (tokens.length === 0) {
    return null;
  }

  const sshIndex = tokens.findIndex((token) => token === "ssh");
  if (sshIndex === -1) {
    return null;
  }

  let destination: string | undefined;
  let username: string | undefined;
  let port: number | undefined;
  let identityFile: string | undefined;
  const tunnels: TunnelConnection[] = [];

  for (let index = sshIndex + 1; index < tokens.length; index++) {
    const token = tokens[index];

    if (token === "--") {
      destination = tokens[index + 1];
      break;
    }

    if (!token.startsWith("-")) {
      if (destination) {
        continue;
      }
      destination = token;
      continue;
    }

    const option = token.slice(1, 2);
    const inlineValue = token.length > 2 ? token.slice(2) : undefined;
    const nextValue = inlineValue ?? tokens[index + 1];
    const optionsWithValue = [
      "b",
      "c",
      "D",
      "E",
      "F",
      "i",
      "J",
      "L",
      "l",
      "m",
      "O",
      "o",
      "p",
      "R",
      "S",
      "W",
      "w",
    ];

    if (!inlineValue && optionsWithValue.includes(option)) {
      index++;
    }

    if (option === "p") {
      port = parsePort(nextValue) ?? port;
    } else if (option === "l") {
      username = nextValue ?? username;
    } else if (option === "i") {
      identityFile = nextValue;
    } else if (option === "L" || option === "R" || option === "D") {
      const tunnel = parseForwardSpec(
        option === "R" ? "remote" : option === "D" ? "dynamic" : "local",
        nextValue ?? "",
      );
      if (tunnel) {
        tunnels.push(tunnel);
      }
    }
  }

  if (!destination) {
    return null;
  }

  const parsedDestination = parseDestination(destination);
  if (!parsedDestination.host) {
    return null;
  }

  const endpointHost =
    parsedDestination.username && parsedDestination.host
      ? `${parsedDestination.username}@${parsedDestination.host}`
      : parsedDestination.host;

  return {
    host: parsedDestination.host,
    username: username ?? parsedDestination.username,
    port: port ?? parsedDestination.port,
    identityFile,
    tunnels: tunnels.map((tunnel) => ({
      ...tunnel,
      endpointHost,
    })),
  };
}
