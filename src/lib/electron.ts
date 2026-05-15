import { isDesktop } from "@/lib/desktop";

export function isElectron(): boolean {
  return isDesktop();
}
