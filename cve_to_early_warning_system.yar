import "vt"

rule cve_early_warning_system
{
	meta:
    	author = "Jesus Toledano"
        date = "May 2023"
        description = "Detect future new exploits. Potential 0-day attacks"
    condition:
        for any tag in vt.metadata.tags : (tag == "cve-2023-23397") 
        or
        for any tag in vt.metadata.tags : (tag == "cve-2023-29324")
}
