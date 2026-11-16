# Checklist des remarques des rapports d'évaluation

Thèse : « A new approach to intelligent intrusion detection in an IoT context based on mobile agents and blockchain » (Khalil Ben Kalboussi)

Sources : [F] Florent Nolot, Reims, 15/11/2026 (avis favorable) ; [G] Gilles Grimaud, Lille, 16/11/2026 (avis favorable avec réserves majeures)

## 1. Structure globale et affirmations

- [ ] [G] L'introduction annonce 8 objectifs, mais seulement 7 questions de recherche sont formulées (section 1.2).
- [ ] [G] Les 7 RQ sont mises en regard des 4 contributions (section 1.3) sans correspondance claire.
- [ ] [G] Pas d'énoncé explicite de la thèse défendue ; le problème est posé, mais pas la thèse.
- [ ] [G] La conclusion ne répond qu'à 4 des 7 RQ.
- [ ] [G] Le regroupement des réponses est discutable : RQ2/RQ3 ne traitent pas de la difficulté du profileur à séparer fenêtres bénignes et malveillantes ; RQ4/RQ5 affirment les bénéfices de l'association agents mobiles + blockchain, non mise en œuvre conjointement ; RQ6 répond par un jeu de données non utilisé pour la validation ; RQ7 n'est que partiellement traitée.
- [ ] [G] Les contributions sont juxtaposées plutôt qu'intégrées ; les liens entre simulateur, profileur, classifieur, agents, blockchain et jeu de données sont faibles.
- [ ] [G] Les conclusions (équilibre précision, coût, temps réel, faisabilité) dépassent ce que les résultats établissent.
- [ ] [G] Le manuscrit et les publications associées diffèrent en expériences, méthodes et résultats ; le lien entre eux n'est pas explicité.
- [ ] [G] Regret qu'un grand modèle de langage ait été utilisé pour rédiger le document.

## 2. Chapitres 1 et 2 : contexte, protocoles, exigences de l'IDS

- [ ] [F] Le chapitre 2 gagnerait à distinguer couches physiques et couches applicatives du modèle TCP/IP, pour montrer ce qu'un IDS peut détecter.
- [ ] [F] Les problèmes de sécurité des couches basses (Wi-Fi, Bluetooth) ne sont pas détectables par un IDS ; à préciser.
- [ ] [F] L'exigence de légèreté de l'IDS n'est justifiée que pour un déploiement embarqué, pas dans le cas général ; à expliquer.
- [ ] [G] Observer le trafic au niveau IP/passerelle fait perdre les informations des couches liaison et physique (BLE, Zigbee, IEEE 802.15.4) ; le choix est concevable mais insuffisamment discuté.
- [ ] [G] L'adaptabilité se réduit à la mise à jour d'un profil statistique et est présentée comme acquise sans justification.
- [ ] [G] Ce qui distingue la démarche d'un IDS IP classique appliqué à l'IoT reste difficile à identifier.

## 3. Chapitre 3 : état de l'art

- [ ] [F] Les définitions des IDS, de leurs types et les critères d'évaluation sont en fin de chapitre ; ils devraient précéder l'état de l'art.
- [ ] [F] Seuls 14 travaux sont comparés dans la matrice ; justifier l'exclusion des autres travaux cités.
- [ ] [F] Le placement des travaux dans la matrice n'est pas justifié (exemple : Shaikh & Gupta [68] inférieur à Javeed et al. [69] sur le temps réel).
- [ ] [F] Référence manquante : Arp et al., « Dos and Don'ts of Machine Learning in Computer Security » (USENIX Security 2022), sur les pièges de l'évaluation en ML pour la sécurité.
- [ ] [G] Les sections 3.9 et 3.11 portent toutes deux le titre « Conclusion ».
- [ ] [G] Plusieurs tableaux sont mal mis en forme et débordent de la marge ; les expressions mathématiques sont présentées de façon compacte.
- [ ] [G] Le propos est parfois décousu.
- [ ] [G] La section 3.7 conclut qu'aucun IDS ne réunit toutes les caractéristiques identifiées, sans montrer en quoi cela constitue un problème scientifique.
- [ ] [G] Le chapitre n'examine pas les méthodologies d'évaluation des IDS réseau IP, ni pourquoi leur transposition à l'IoT exige d'autres critères ou protocoles.
- [ ] [G] La section 3.10 liste des métriques sans constituer une méthodologie d'évaluation.

## 4. Chapitre 4 : environnement de simulation INIT

- [ ] [F] Seulement 50 objets IoT testés ; c'est peu (un logement domotique peut atteindre ce nombre). Préciser si le framework couvre seulement des environnements domestiques ou aussi des bâtiments.
- [ ] [F] La méthode d'attaque des objets LoRaWAN et la simulation de la passerelle LoRaWAN ne sont pas expliquées.
- [ ] [F] La liaison entre équipements physiques, serveur EVE-NG et interfaces réseau virtuelles n'est pas claire.
- [ ] [F] Le simulateur nécessite plus d'explications sur les interactions internes et des tests de pertinence par rapport à un environnement réel. S'agit-il d'un jumeau numérique ?
- [ ] [F] La section 4.4 annonce des tests d'IDS sans aucun résultat ; l'apport du machine learning à la détection n'est pas précisé.
- [ ] [G] Le manuscrit confond ce qui a été réalisé, ce qui pourrait être observé et ce qui n'est qu'envisagé (protocoles pris en charge, nombre d'équipements, couches observables).
- [ ] [G] Quelles parties de l'architecture sont effectivement implantées et expérimentées n'est pas clair.
- [ ] [G] La notion de « simulation » est imprécise : exécution de micrologiciel, reproduction de trafic, ou simulation probabiliste ?
- [ ] [G] Le réalisme revendiqué (section 4.4) n'est étayé par aucune comparaison quantitative avec des traces de logements réels ; aucun critère de proximité n'est donné.
- [ ] [G] La coexistence d'équipements physiques et virtuels ne suffit pas à revendiquer ce réalisme.
- [ ] [G] Des travaux antérieurs montrant que le contexte spatial, physique et humain détermine le trafic domotique sont absents (le relecteur cite Azizi et al., CPSIoTSec 2025).
- [ ] [G] Les activités des habitants et les phénomènes physiques affectant les capteurs ne sont pas représentés ; les modéliser suppose de les avoir pré-identifiés, ce qui limite l'intérêt du machine learning.

## 5. Chapitre 5 : profileur + IDS CNN-LSTM à deux étages

- [ ] [F] Le jeu de données ToN-IoT est utilisé sans être défini.
- [ ] [F] Les résultats ne sont pas comparés à la littérature.
- [ ] [F] Tableau 5.1 : avec un seuil de 0,7, tous les paquets passent au classifieur. En baissant le seuil, on filtre, mais le macro-F1 passe sous 0,80, en deçà des travaux existants.
- [ ] [F] Le résumé annonce 98,24 % de précision sur ToN-IoT, 96,84 % sur Bot-IoT, environ 90 % du trafic normal filtré et 40 à 60 % de réduction de calcul ; le tableau 5.2 donne d'autres chiffres.
- [ ] [F] Il n'est pas précisé si le sur-échantillonnage est appliqué avant ou après la séparation train/test, ce qui risque de biaiser les résultats.
- [ ] [F] L'apport du profilage n'est pas démontré.
- [ ] [G] L'adaptabilité du profileur repose sur la comparaison de deux fenêtres successives ; cela ne montre pas que les évolutions légitimes propres à chaque objet sont apprises.
- [ ] [G] L'IDS n'est évalué ni sur une passerelle contrainte, ni dans l'environnement INIT. Pourquoi ?
- [ ] [G] L'évaluation utilise une machine haut de gamme (i7-12700K, 32 Go, RTX 3080), très éloignée d'une passerelle domestique.
- [ ] [G] Un Raspberry Pi est évoqué pour la supervision, mais aucune expérience de déploiement sur ce type de cible n'est rapportée.
- [ ] [G] Les résultats « temps réel » sont simulés ; aucun trafic capturé en direct n'est utilisé.
- [ ] [G] Les composants réellement déployés ensemble ne sont pas clairs ; le périmètre des mesures de ressources et la construction des séquences soumises au CNN ne le sont pas non plus.
- [ ] [G] Contradiction avec l'article publié : l'article annonce que le profileur filtre 80 à 90 % du trafic et « maintains 98% accuracy under realistic temporal constraints » ; le chapitre dit que le taux de délestage et le taux de fuite évoluent de concert et que l'indice de profil ne sépare pas les fenêtres bénignes des malveillantes.
- [ ] [G] Tableau 5.1 au seuil 0,2 : 84,7 % du trafic est écarté, mais aussi 84,7 % des attaques, et le macro-F1 tombe à 0,297. Cela remet en cause le compromis coût/détection présenté comme conclusion principale.
- [ ] [G] La formule du seuil Δ = (nPI/oPI) × 100 donne 100 % pour des profils identiques et reste ambiguë. Quelle expression a été implantée : celle du manuscrit ou celle de l'article ?
- [ ] [G] Contradiction temporelle : l'article affirme injecter les paquets selon leurs horodatages originaux ; le chapitre indique que les données ToN-IoT ne sont pas horodatées et que les fenêtres suivent l'ordre des flux.
- [ ] [G] Chiffres discordants entre article et chapitre : ToN-IoT sans ADASYN, 68,52 % (article) contre 41,2 % (tableau 5.2) ; avec ADASYN, 98,24 % contre 97,1 %. Bot-IoT passe de 68,52 % à 58,3 % et de 96,84 % à 96,35 %. Le tableau comparatif de l'article donne 97,24 %.
- [ ] [G] Les expériences ne sont pas identifiées et les protocoles menant aux résultats ne sont pas décrits ; les écarts ne peuvent être compris et la reproductibilité n'est pas établie.

## 6. Chapitre 6 : IDS distribué à agents mobiles + blockchain

- [ ] [F] Le chapitre est cohérent et les mesures blockchain sont rigoureuses, mais l'étude gagnerait à être approfondie.
- [ ] [F] L'impact de la migration d'agent sur la latence, la bande passante et la sécurisation de la liaison n'est pas étudié.
- [ ] [F] La réduction de ToN-IoT à 5 classes empêche la comparaison avec les résultats du chapitre 5.
- [ ] [G] L'architecture est décrite essentiellement au niveau conceptuel ; la reproduction des expériences est difficile.
- [ ] [G] L'apprentissage fédéré semble simulé (section 6.6).
- [ ] [G] La blockchain a fait l'objet de mesures séparées du reste du système.
- [ ] [G] La négociation entre agents et leur migration n'ont pas été caractérisées expérimentalement.
- [ ] [G] Ce qui « migre » n'est pas clair : code de l'agent, état, modèle d'apprentissage, ou tâche d'analyse ? Sur quel équipement l'inférence est-elle exécutée ?
- [ ] [G] Descriptions contradictoires : le manuscrit dit qu'un agent d'environ 200 ko, incluant le modèle de détection, migre vers le nœud concerné ; ailleurs, les objets contraints n'hébergent que le profileur léger et les traitements sont faits sur les passerelles. L'algorithme indique que l'agent charge le modèle après migration.
- [ ] [G] En raison de ces contradictions, l'apport de la mobilité des agents par rapport à une simple répartition dynamique des traitements entre passerelles ne peut être apprécié.
- [ ] [G] Le coût en latence de la migration dans le système global n'est pas quantifié.
- [ ] [G] L'article associé indique que les traces réseau, les scripts d'attaque et le code des agents mobiles ne sont pas publiés.

## 7. Chapitre 7 : jeu de données IoT réel

- [ ] [F] Contenu : 12 jours de trafic normal + 2 jours d'attaques, routeur sous OpenWrt, 15 équipements. La démarche d'anonymisation est solide.
- [ ] [F] Rien ne garantit que le trafic « légitime » le soit réellement. Un IDS ou un autre outil de sécurité a-t-il été utilisé pour le vérifier ?
- [ ] [F] Les familles d'attaques sont peu diversifiées : DoS, désauthentification Wi-Fi et ARP spoofing seulement. Scans lents, botnets, injections MQTT et exfiltrations sont absents. Certaines attaques sortent du cadre habituel des tests d'intrusion autorisés.
- [ ] [F] La suppression d'éléments de la charge utile réduit la pertinence du jeu de données ; son impact doit être quantifié.
- [ ] [F] Coquille : « 1é jours » (probablement « 12 jours »).
- [ ] [G] Les journées normales constituent une trace « réelle » valable, mais les attaques sont courtes, plus démonstratives qu'effectives, et proches des scénarios artificiels et répétitifs que l'auteur critique en section 7.2.
- [ ] [G] Le corpus ne couvre que ce qui est visible sur l'interface IP du routeur ; il ne donne accès ni à la couche physique ni à la couche liaison, pourtant invoquées dans la motivation du chapitre.
- [ ] [G] Trames de désauthentification Wi-Fi : comment ont-elles été capturées et étiquetées, alors que la collecte s'est faite sur l'interface de pont du routeur, où elles ne sont visibles que via l'interface radio ?
- [ ] [G] Étiquetage par fenêtres horaires : distingue-t-il le trafic légitime qui continue pendant les fenêtres d'attaque ?
- [ ] [G] L'anonymisation porte surtout sur les adresses ; une suppression partielle des contenus protège-t-elle les noms de domaine, identifiants applicatifs et informations personnelles transmises en clair par les objets ?
- [ ] [G] Aucun lien d'accès au jeu de données (annoncé soumis à IEEE DataPort), ni aux scripts d'attaque et d'anonymisation.
- [ ] [G] Les IDS des chapitres 5 et 6 ne sont pas évalués sur ces traces.
- [ ] [G] La pertinence scientifique du corpus et sa capacité à valider les contributions sont annoncées mais non démontrées.

## 8. Chapitre 8 : conclusion

- [ ] [G] Les réponses aux 7 RQ sont regroupées en 4 blocs que le relecteur juge peu convaincants (voir section 1).

## 9. Coquilles et langue (Nolot)

- [ ] « sr les IDS » → « sur les IDS »
- [ ] « leger » → « léger » (apparaît plusieurs fois)
- [ ] « calcul un rapport » → « calcule un rapport »
- [ ] « faisant parti » → « faisant partie »
- [ ] « en dehors de attaques » → « en dehors des attaques »
- [ ] « couches physiques et de couches applicatives » → « couches physiques et applicatives »
- [ ] Vérifier la référence « paragraphe 4.4 » par rapport à la numérotation réelle

## 10. Divergences ou accents différents entre les deux relecteurs

- [ ] Bénéfice du profileur : Nolot le dit « non démontré » ; Grimaud estime que les chiffres de l'article sont contredits par le tableau 5.1. Même faiblesse, formulée plus fortement par Grimaud.
- [ ] Réalisme du trafic : Nolot demande si le trafic légitime est vérifié ; Grimaud accepte les journées normales comme « réelles » et questionne plutôt les attaques.
- [ ] Position générale : Nolot est sans réserve ; Grimaud est favorable avec des réserves majeures sur l'intégration, la reproductibilité et la cohérence article/manuscrit.
