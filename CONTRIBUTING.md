# Guide de Contribution

Merci de l'int\u00e9r\u00eat que vous portez au Projet Androm\u00e8de! Ce document explique comment contribuer efficacement \u00e0 notre initiative d'antivirus next-gen.

## \ud83c\udf1f Comment Contribuer

### Signaler des Bugs

1. V\u00e9rifiez d'abord si le bug n'a pas d\u00e9j\u00e0 \u00e9t\u00e9 signal\u00e9 dans les [issues](https://github.com/servais1983/projet-andromede/issues)
2. Utilisez le template \"Bug Report\" pour cr\u00e9er une nouvelle issue
3. Incluez des \u00e9tapes d\u00e9taill\u00e9es pour reproduire le probl\u00e8me
4. Ajoutez des captures d'\u00e9cran si pertinent

### Sugg\u00e9rer des Am\u00e9liorations

1. Utilisez le template \"Feature Request\" dans les issues
2. Expliquez clairement le besoin et les b\u00e9n\u00e9fices attendus
3. Si possible, proposez une approche d'impl\u00e9mentation

### Soumettre du Code

1. Forker le d\u00e9p\u00f4t
2. Cr\u00e9er une branche d\u00e9di\u00e9e (`git checkout -b feature/amazing-feature`)
3. Commiter vos changements (`git commit -m 'feat: Add amazing feature'`)
4. Pousser vers la branche (`git push origin feature/amazing-feature`)
5. Ouvrir une Pull Request

## \ud83d\udcdd Style de Code

### Python

- Suivez PEP 8
- Utilisez des docstrings au format Google
- Testez votre code avec pytest

### Commit Messages

Nous suivons la convention [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Types de commit:
- `feat`: Nouvelle fonctionnalit\u00e9
- `fix`: Correction de bug
- `docs`: Documentation uniquement
- `style`: Changements de style sans impact fonctionnel
- `refactor`: Refactorisation sans changement fonctionnel
- `perf`: Am\u00e9liorations de performances
- `test`: Ajout ou correction de tests
- `build`: Modifications du build/syst\u00e8me de CI

## \ud83d\udee1\ufe0f S\u00e9curit\u00e9

### Signaler une Vuln\u00e9rabilit\u00e9

Pour les probl\u00e8mes de s\u00e9curit\u00e9 sensibles, n'utilisez PAS les issues publiques. Envoyez plut\u00f4t un email \u00e0 security@projet-andromede.org avec les d\u00e9tails.

### Bonnes Pratiques

- Ne commitez jamais de credentials
- Ne d\u00e9sactivez pas les v\u00e9rifications de s\u00e9curit\u00e9
- Utilisez toujours des biblioth\u00e8ques \u00e0 jour

## \ud83d\udca1 Id\u00e9es de Contribution

Si vous voulez contribuer mais ne savez pas par o\u00f9 commencer, voici quelques id\u00e9es:

- Am\u00e9lioration des tests
- Documentation et tutoriels
- Optimisation des performances
- Int\u00e9gration avec d'autres outils de s\u00e9curit\u00e9
- Support de nouvelles plateformes

## \ud83d\udcee Process de Review

- Chaque Pull Request n\u00e9cessite au moins une approbation
- Les tests automatis\u00e9s doivent passer
- Le code doit respecter les standards du projet
- Des explications claires doivent accompagner les changements complexes

## \ud83d\udc64 Accr\u00e9ditation des Contributeurs

Tous les contributeurs sont list\u00e9s dans le fichier [CONTRIBUTORS.md](CONTRIBUTORS.md). Assurez-vous d'y ajouter votre nom lors de votre premi\u00e8re contribution!

## \ud83d\udc4b Communaut\u00e9

- Rejoignez notre [serveur Discord](https://discord.gg/projet-andromede)
- Suivez notre [blog technique](https://tech.projet-andromede.org)
- Participez \u00e0 nos appels mensuels de contributeurs

Nous sommes impatients de voir vos contributions et de construire ensemble l'avenir de la cybers\u00e9curit\u00e9!