# Fighting Fire with Fire (pt-BR: Apagando fogo com Gasolina)

Slides **created for [DevOpsDays Brasília 2026](https://devopsdaysbsb.com.br/)** (Nov 14, 2026, ParlaMundi),
by [Odilon Junior](https://odilon.dev/): how AI and LLMs change the DevOps engineer's day with CVEs and incidents.

- Slides (EN / pt-BR) and PDFs: https://odilhao.github.io/devopsdaysbsb2026/
- Every build downloads the public data again, so **the charts show the day the workflow ran**.
  The cover slide says which day that was.

Odilon Junior: [LinkedIn](https://www.linkedin.com/in/odilonjunior/) · [GitHub](https://github.com/Odilhao) · [blog](https://odilon.dev/)

## How it is built

`.github/workflows/slides.yml` fetches the public data, scans a container image, computes the numbers, fills the
Markdown from one template (`slides/deck.md.j2` + `slides/i18n/*.yaml`), then lints, builds and exports with
[Slidev](https://sli.dev/) + [tahta](https://github.com/zcag/tahta). It publishes the sites to GitHub Pages and
the PDFs as the run's artifact. It runs on push to `main`, manually, and on talk day (Nov 14, 2026).

Locally: `scripts/build.sh` (needs python3, podman or docker, node 22).

## Sources

Data pulled by the build: [CVE.org cvelistV5](https://github.com/CVEProject/cvelistV5) ·
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) ·
[GitHub Advisory Database](https://docs.github.com/en/rest/security-advisories/global-advisories) ·
[NVD API](https://nvd.nist.gov/developers/vulnerabilities) · [Trivy](https://github.com/aquasecurity/trivy) 0.58.1 and
[Grype](https://github.com/anchore/grype) 0.86.1 (pinned in `scripts/scan_images.sh`).

Articles behind the numbers that are not computed (full list with quotes: `data/manual/article_facts.yaml`):

- Kernel TCP (CVE-2026-98432): [fix commit e3f33b0a1d89](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e3f33b0a1d89d738e2b913dab519226eaf76e15b) ·
  [Anthropic](https://www.anthropic.com/research/discovering-vulnerabilities-with-claude)
- Finding got cheap: [Mozilla](https://blog.mozilla.org/en/privacy-security/ai-security-zero-day-vulnerabilities/) · [AISLE](https://aisle.com/blog/aisle-year-on-the-cyber-frontier) · [sshhole.com](https://sshhole.com/)
- Dependencies: [GitLab 19.5.1 patch release](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/) ·
  [Ruby regexp fixes](https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/) ·
  [Node.js October 2026 releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) ·
  [Pillow #10337](https://github.com/python-pillow/Pillow/issues/10337)
- OpenVox / Puppet: [Puppet's 2025 plans](https://www.puppet.com/blog/open-source-puppet-updates-2025) ·
  [Vox Pupuli on the Perforce EULA](https://dev.to/voxpupuli/the-perforce-eula-and-impact-on-vox-pupuli-4lic) ·
  releases [8.31.1](https://github.com/OpenVoxProject/openvox/releases/tag/8.31.1), [8.31.2](https://github.com/OpenVoxProject/openvox/releases/tag/8.31.2), [8.32.0](https://github.com/OpenVoxProject/openvox/releases/tag/8.32.0) ·
  [puppet-runtime #321](https://github.com/OpenVoxProject/puppet-runtime/pull/321), [#322](https://github.com/OpenVoxProject/puppet-runtime/pull/322)
- Embargo: [PHP Foundation security release post](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)
- People are the perimeter: [Railway incident report](https://blog.railway.com/p/incident-report-october-security-incident) ·
  [Wiz, Black October](https://www.wiz.io/blog/black-october-for-ai-developer-platforms) ·
  [Aikido](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories) ·
  [Chainguard](https://www.chainguard.dev/unchained/wfx-loot-stolen-github-tokens-pushed-a-ci-secret-stealer-into-60-000-repositories-november-2026) ·
  CoinDesk on Binance ([Oct 30](https://www.coindesk.com/tech/2026/10/30/binance-uncovers-wider-breach-in-usd6-3-billion-exploit-targets-sunday-withdrawal-restart), [Nov 3](https://www.coindesk.com/business/2026/11/03/binance-s-usd6-3-billion-hack-began-with-a-fake-job-interview-exchange-says); press coverage of a Binance briefing, not a post-mortem)

The scan step uses `node:20` only to show how far two scanners can disagree on one image.

## License

Unless otherwise noted, this project's source code and slide content are licensed under the GNU General Public License v3.0 or (at your option) any later version. See [LICENSE](LICENSE). Third-party software, source material, and data remain subject to their respective terms.
