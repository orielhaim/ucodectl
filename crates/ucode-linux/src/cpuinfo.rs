use std::path::Path;

use ucode_core::{CpuIdentity, CpuSignature, Vendor};

use crate::{LinuxError, Result};

/// One logical CPU as reported by `/proc/cpuinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuInfoCpu {
    pub processor: u32,
    pub vendor: Vendor,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub microcode: Option<u32>,
    pub physical_id: Option<u32>,
    pub core_id: Option<u32>,
}

impl CpuInfoCpu {
    pub fn signature(&self) -> CpuSignature {
        CpuSignature::from_fms(self.vendor, self.family, self.model, self.stepping)
    }

    pub fn to_identity(&self) -> CpuIdentity {
        let mut id = CpuIdentity::new(self.vendor, self.signature());
        if let Some(rev) = self.microcode {
            id = id.with_revision(rev);
        }
        id
    }
}

/// Parse `/proc/cpuinfo` text.
pub fn parse_cpuinfo(text: &str) -> Result<Vec<CpuInfoCpu>> {
    let mut cpus = Vec::new();
    let mut cur: PartialCpu = PartialCpu::default();

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            if let Some(cpu) = cur.finish() {
                cpus.push(cpu);
            }
            cur = PartialCpu::default();
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "processor" => cur.processor = value.parse().ok(),
            "vendor_id" => cur.vendor = Vendor::from_cpuid_string(value),
            "cpu family" => cur.family = parse_u32(value),
            "model" => cur.model = parse_u32(value),
            "stepping" => cur.stepping = parse_u32(value),
            "microcode" => cur.microcode = parse_hex_or_dec(value),
            "physical id" => cur.physical_id = parse_u32(value),
            "core id" => cur.core_id = parse_u32(value),
            _ => {}
        }
    }
    if let Some(cpu) = cur.finish() {
        cpus.push(cpu);
    }

    if cpus.is_empty() {
        return Err(LinuxError::Parse {
            what: "cpuinfo",
            reason: "no processor blocks found".to_string(),
        });
    }
    Ok(cpus)
}

/// Read and parse `/proc/cpuinfo`.
pub fn read_cpuinfo(path: &Path) -> Result<Vec<CpuInfoCpu>> {
    let text = std::fs::read_to_string(path).map_err(|e| LinuxError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_cpuinfo(&text)
}

#[derive(Default)]
struct PartialCpu {
    processor: Option<u32>,
    vendor: Option<Vendor>,
    family: Option<u32>,
    model: Option<u32>,
    stepping: Option<u32>,
    microcode: Option<u32>,
    physical_id: Option<u32>,
    core_id: Option<u32>,
}

impl PartialCpu {
    fn finish(&self) -> Option<CpuInfoCpu> {
        Some(CpuInfoCpu {
            processor: self.processor?,
            vendor: self.vendor?,
            family: self.family?,
            model: self.model?,
            stepping: self.stepping?,
            microcode: self.microcode,
            physical_id: self.physical_id,
            core_id: self.core_id,
        })
    }
}

fn parse_u32(s: &str) -> Option<u32> {
    s.trim().parse().ok()
}

fn parse_hex_or_dec(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_cpus() {
        let text = "\
processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 140
stepping\t: 1
microcode\t: 0xb4
physical id\t: 0
core id\t\t: 0

processor\t: 1
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 140
stepping\t: 1
microcode\t: 0xb4
physical id\t: 0
core id\t\t: 1
";
        let cpus = parse_cpuinfo(text).unwrap();
        assert_eq!(cpus.len(), 2);
        assert_eq!(cpus[0].vendor, Vendor::Intel);
        assert_eq!(cpus[0].microcode, Some(0xb4));
        assert_eq!(cpus[0].signature().model_for(Vendor::Intel), 140);
    }
}
