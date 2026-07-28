# DMARC Dashboard Plus – Portainer

En let selvhostet DMARC-løsning i én container, uden Elasticsearch/Kibana.

## Funktioner

- Upload af DMARC aggregate `.xml`, `.xml.gz` og `.zip`
- Upload af SMTP TLS-RPT `.json` og ZIP-filer med JSON
- Automatisk IMAP-import
- Arkivering af behandlede mails til valgfri IMAP-mappe
- Dubletkontrol
- Dashboard med DMARC-, DKIM- og SPF-tal
- Tidsudvikling og dispositioner
- Filtrering efter domæne og periode
- Detaljevisning af hver rapport
- CSV-eksport
- Importlog
- SQLite i persistent Docker-volume
- HTTP Basic Authentication

## Portainer

1. Læg mappen i et Git-repository.
2. Portainer → Stacks → Add stack → Repository.
3. Repository URL: dit repository.
4. Compose path: `docker-compose.yml`.
5. Ret miljøvariabler i Portainer eller Compose-filen.
6. Deploy stacken.
7. Åbn `http://SERVER-IP:8088`.

## Vigtige variabler

- `ADMIN_USER` og `ADMIN_PASSWORD`
- `IMAP_ENABLED=true`
- `IMAP_HOST`, `IMAP_USER`, `IMAP_PASSWORD`
- `IMAP_ARCHIVE_FOLDER=DMARC-Processed`
- `IMAP_POLL_MINUTES=15`

Microsoft 365 tillader ofte ikke almindelig IMAP-adgangskode. I så fald skal postkassen enten have en understøttet IMAP-loginmetode, eller appen skal senere udvides med Microsoft Graph/OAuth.

## Backup

```bash
docker run --rm -v dmarc-dashboard_dmarc_data:/data -v "$PWD":/backup alpine tar czf /backup/dmarc-data-backup.tar.gz -C /data .
```
