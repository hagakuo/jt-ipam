/**
 * 「虛實」的標籤：虛擬化整合對應到的是哪一種客體（使用者要求，2026-10-02：PVE 有 KVM／LXC 兩種）。
 *
 * PVE：kind="vm"（qemu）＝KVM 虛擬機、kind="ct"（lxc）＝LXC 容器；VMware 的都是虛擬機。
 * 平台或種類不明時只回大類，不猜。
 */
export interface VirtMatch { vm?: string; cluster?: string | null; platform?: string | null; kind?: string | null }

export function virtTagText(v: VirtMatch, t: (k: string) => string): string {
  const isCt = v.kind === "ct";
  const base = isCt ? t("addresses.virt_ct_tag") : t("addresses.virt_vm_tag");
  const tech = v.platform === "proxmox" ? (isCt ? "LXC" : v.kind === "vm" ? "KVM" : "")
    : v.platform === "vmware" ? "VMware" : "";
  return tech ? `${base} · ${tech}` : base;
}
