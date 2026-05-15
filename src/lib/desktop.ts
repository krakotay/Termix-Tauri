type DesktopWindow = Window &
  typeof globalThis & {
    __TAURI__?: unknown;
    __TAURI_INTERNALS__?: unknown;
    IS_ELECTRON?: boolean;
    electronAPI?: {
      isElectron?: boolean;
      invoke?: (channel: string, ...args: unknown[]) => Promise<unknown>;
    };
  };

const tauriCommandNames: Record<string, string> = {
  "get-app-version": "get_app_version",
  "get-platform": "get_platform",
  "get-server-config": "get_server_config",
  "save-server-config": "save_server_config",
  "test-server-connection": "test_server_connection",
  "get-embedded-server-status": "get_embedded_server_status",
};

export function isTauri(): boolean {
  if (typeof window === "undefined") return false;

  const win = window as DesktopWindow;
  return !!win.__TAURI__ || !!win.__TAURI_INTERNALS__;
}

export function isDesktop(): boolean {
  if (typeof window === "undefined") return false;

  const win = window as DesktopWindow;
  return (
    isTauri() ||
    win.IS_ELECTRON === true ||
    !!win.electronAPI ||
    win.electronAPI?.isElectron === true
  );
}

export async function invokeDesktop<T>(
  channel: string,
  ...args: unknown[]
): Promise<T> {
  if (isTauri()) {
    const { invoke } = await import("@tauri-apps/api/core");
    const command = tauriCommandNames[channel] || channel.replaceAll("-", "_");
    const payload =
      channel === "save-server-config"
        ? { config: args[0] }
        : channel === "test-server-connection"
          ? { serverUrl: args[0] }
          : args.length === 1 && typeof args[0] === "object" && args[0] !== null
            ? (args[0] as Record<string, unknown>)
            : {};

    return invoke<T>(command, payload);
  }

  const electronInvoke = (window as DesktopWindow).electronAPI?.invoke;
  if (electronInvoke) {
    return electronInvoke(channel, ...args) as Promise<T>;
  }

  throw new Error("Desktop bridge is not available");
}
