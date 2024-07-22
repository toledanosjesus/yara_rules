import "vt"

rule namecheap_crowd_domains
{
  meta:
    author = "GSA Threat Intel Team"
    description = "Livehunt rule to track potential fake domains impersonating Crowdstrike"
    target_entity = "domain"
    sample_1 = "crowdfalcon-immed-update.com"
    sample_2 = "crowdstrike-bsod.com"
    gti_search = "https://www.virustotal.com/gui/search/entity%253Adomain%2520registrar%253Anamecheap%2520creation_date%253A7d%252B%2520%2520domain%253A*crowd*/domains"
  condition:
    vt.net.domain.new_domain and
    vt.net.domain.whois["Registrar"] == "NAMECHEAP INC | NameCheap, Inc." and
    ( 
        vt.net.domain.raw icontains "crowd" or
        vt.net.ip.reverse_lookup icontains "crowd"
    )
}

rule favicon_crowd_domains {
  meta:
    author = "GSA Threat Intel Team"
    description = "Livehunt rule to track potential fake domains impersonating Crowdstrike"
    target_entity = "domain"
    sample_1 = "crowdstrike.blue"
    sample_2 = "crowdstrife.com"
    gti_search = "https://www.virustotal.com/gui/search/entity%253Adomain%2520(main_icon_dhash%253Ac0cc9efcc086c6f0%2520or%2520main_icon_dhash%253A4cb269ccd4d4e803)%2520creation_date%253A7d%252B/domains"
  condition:
    vt.net.domain.new_domain and
    ( vt.net.domain.favicon.dhash == "c0cc9efcc086c6f0" or
        vt.net.domain.favicon.dhash == "4cb269ccd4d4e803" )
}
