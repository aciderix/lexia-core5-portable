# Lexia Core5 Portable Builder

Ce repo contient un GitHub Actions workflow qui :
1. Installe Lexia Core5 sur un runner Windows (VM native, pas de container)
2. Copie tous les fichiers installés (app + runtime AIR)
3. Lance l'app et prend une capture d'écran
4. Upload le tout en artifact téléchargeable

## Utilisation

1. Crée un repo sur GitHub (public ou privé)
2. Copie le contenu de ce dossier dedans
3. Ajoute `lexia-installer.exe` à la racine du repo (ou héberge-le et modifie le workflow pour le télécharger)
4. Va dans **Actions** > **Build Lexia Core5 Portable** > **Run workflow**
5. Attends ~5 minutes
6. Télécharge les artifacts :
   - `lexia-core5-portable` — l'app complète portable
   - `lexia-screenshots` — capture d'écran de l'interface

## Notes

- Le runner Windows est une vraie VM avec support 32-bit natif
- Pas de restriction réseau (contrairement à notre sandbox)
- L'artifact reste disponible 30 jours
- Le workflow est déclenché manuellement (workflow_dispatch)
