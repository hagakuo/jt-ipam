/** 探測所需的系統工具怎麼裝。
 *
 * 這段原本在「掃描代理」與「子網路編輯」各有一份，而且已經不一樣了 —— mdns 那行
 * 只有其中一份提到會順便啟動 avahi-daemon、開 UDP 5353。同一句話在兩個入口講得不同，
 * 使用者會以為兩邊是兩回事。
 */
import { SUDO } from "@/utils/sudo";

type Translate = (key: string) => string;

export function probeInstall(key: string, t: Translate): string {
  switch (key) {
    case "os":
    case "ports":
      return `${SUDO} apt install nmap`;
    case "netbios":
      return `${SUDO} apt install samba-common-bin   # ${t("scan_probes.provides_nmblookup")}`;
    case "mdns":
      return `${SUDO} apt install avahi-utils   # ${t("scan_probes.provides_avahi")}`;
    default:
      return t("scan_probes.install_generic");
  }
}
