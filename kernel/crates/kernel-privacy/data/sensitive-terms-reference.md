# Sensitive-terms reference list

Coverage is promised for this list. Every entry below is masked in each language
where it has a form, and every form is a row of `sensitive-terms-v1.tsv`. A term
outside this list is backlog, not a P2 defect.

Sources. The condition names follow the ICD-11 chapter titles (WHO) and the
common names in each chapter. The drug names are INN names (WHO INN list); the
brand names are the product names of common medicines. The French lay names
follow the public health portals (ameli.fr). The Afrikaans, Hungarian, Slovene
and Chinese forms are drafted translations, not yet checked against the national
health portals: a reviewer should confirm them before a release.

Conventions. A cell is the exact term in its language; `—` means the language has
no form. Hungarian `rák` (cancer) is matched by the accent rule in code, not by a
row, so its cell is marked as such. A bare Slovene `rak` is cue-gated (see the
lexicon header).

## Conditions

| id | category | EN | FR | AF | HU | SL | ZH | source |
|---|---|---|---|---|---|---|---|---|
| C001 | HEALTH | cancer | cancer | kanker | rák | rak | 癌症 | ICD-11 neoplasms |
| C002 | HEALTH | breast cancer | cancer du sein | borskanker | mellrák | rak dojke | 乳腺癌 | ICD-11 neoplasms |
| C003 | HEALTH | lung cancer | cancer du poumon | longkanker | tüdőrák | pljučni rak | 肺癌 | ICD-11 neoplasms |
| C004 | HEALTH | colorectal cancer | cancer colorectal | dikderm-kanker | vastagbélrák | rak debelega črevesa | 大肠癌 | ICD-11 neoplasms |
| C005 | HEALTH | prostate cancer | cancer de la prostate | prostaatkanker | prosztatarák | rak prostate | 前列腺癌 | ICD-11 neoplasms |
| C006 | HEALTH | leukaemia | leucémie | leukemie | leukémia | levkemija | 白血病 | ICD-11 neoplasms |
| C007 | HEALTH | lymphoma | lymphome | limfoom | limfóma | limfom | 淋巴瘤 | ICD-11 neoplasms |
| C008 | HEALTH | melanoma | mélanome | melanoom | melanóma | melanom | 黑色素瘤 | ICD-11 neoplasms |
| C009 | HEALTH | tumour | tumeur | tumor | daganat | tumor | 肿瘤 | ICD-11 neoplasms |
| C010 | HEALTH | carcinoma | carcinome | karsinoom | karcinóma | karcinom | 癌 | ICD-11 neoplasms |
| C011 | HEALTH | cervical cancer | cancer du col de l'utérus | servikale kanker | méhnyakrák | rak materničnega vratu | 宫颈癌 | ICD-11 neoplasms |
| C012 | HEALTH | skin cancer | cancer de la peau | velkanker | bőrrák | rak kože | 皮肤癌 | ICD-11 neoplasms |
| C013 | HEALTH | diabetes | diabète | diabetes | cukorbetegség | sladkorna bolezen | 糖尿病 | ICD-11 endocrine |
| C014 | HEALTH | obesity | obésité | obesiteit | elhízás | debelost | 肥胖症 | ICD-11 endocrine |
| C015 | HEALTH | thyroid disorder | trouble thyroïdien | skildklierafwyking | pajzsmirigy-betegség | bolezen ščitnice | 甲状腺疾病 | ICD-11 endocrine |
| C016 | HEALTH | gout | goutte | jig | köszvény | protin | 痛风 | ICD-11 musculoskeletal |
| C017 | HEALTH | depression | dépression | depressie | depresszió | depresija | 抑郁症 | ICD-11 mental disorders |
| C018 | HEALTH | anxiety disorder | trouble anxieux | angsversteuring | szorongásos zavar | anksiozna motnja | 焦虑症 | ICD-11 mental disorders |
| C019 | HEALTH | bipolar disorder | trouble bipolaire | bipolêre versteuring | bipoláris zavar | bipolarna motnja | 双相情感障碍 | ICD-11 mental disorders |
| C020 | HEALTH | schizophrenia | schizophrénie | skisofrenie | skizofrénia | shizofrenija | 精神分裂症 | ICD-11 mental disorders |
| C021 | HEALTH | obsessive-compulsive disorder | trouble obsessionnel compulsif | dwangneurose | kényszerbetegség | obsesivno-kompulzivna motnja | 强迫症 | ICD-11 mental disorders |
| C022 | HEALTH | post-traumatic stress disorder | état de stress post-traumatique | posttraumatiese stresversteuring | posttraumás stresszzavar | posttravmatska stresna motnja | 创伤后应激障碍 | ICD-11 mental disorders |
| C023 | HEALTH | ADHD | TDAH | ADHD | ADHD | ADHD | 注意缺陷多动障碍 | ICD-11 mental disorders |
| C024 | HEALTH | autism | autisme | outisme | autizmus | avtizem | 自闭症 | ICD-11 mental disorders |
| C025 | HEALTH | eating disorder | trouble alimentaire | eetversteuring | evészavar | motnja hranjenja | 进食障碍 | ICD-11 mental disorders |
| C026 | HEALTH | anorexia | anorexie | anoreksie | anorexia | anoreksija | 厌食症 | ICD-11 mental disorders |
| C027 | HEALTH | bulimia | boulimie | bulimie | bulimia | bulimija | 暴食症 | ICD-11 mental disorders |
| C028 | HEALTH | insomnia | insomnie | slaaploosheid | álmatlanság | nespečnost | 失眠症 | ICD-11 sleep-wake disorders |
| C029 | HEALTH | panic disorder | trouble panique | paniekversteuring | pánikbetegség | panična motnja | 惊恐障碍 | ICD-11 mental disorders |
| C030 | HEALTH | dementia | démence | demensie | demencia | demenca | 痴呆 | ICD-11 nervous system |
| C031 | HEALTH | Alzheimer | Alzheimer | Alzheimer | Alzheimer | Alzheimerjeva bolezen | 阿尔茨海默病 | ICD-11 nervous system |
| C032 | HEALTH | alcohol dependence | alcoolisme | alkoholisme | alkoholizmus | alkoholizem | 酒精依赖 | ICD-11 mental disorders |
| C033 | HEALTH | drug addiction | toxicomanie | dwelmverslawing | kábítószer-függőség | odvisnost od drog | 药物成瘾 | ICD-11 mental disorders |
| C034 | HEALTH | addiction | addiction | verslawing | függőség | zasvojenost | 成瘾 | ICD-11 mental disorders |
| C035 | HEALTH | suicide | suicide | selfmoord | öngyilkosság | samomor | 自杀 | ICD-11 mental disorders |
| C036 | HEALTH | self-harm | automutilation | selfbeskadiging | önsértés | samopoškodovanje | 自残 | ICD-11 mental disorders |
| C037 | HEALTH | burnout | épuisement professionnel | uitbranding | kiégés | izgorelost | 职业倦怠 | ICD-11 factors influencing health |
| C038 | HEALTH | epilepsy | épilepsie | epilepsie | epilepszia | epilepsija | 癫痫 | ICD-11 nervous system |
| C039 | HEALTH | multiple sclerosis | sclérose en plaques | veelvuldige sklerose | szklerózis multiplex | multipla skleroza | 多发性硬化 | ICD-11 nervous system |
| C040 | HEALTH | Parkinson | maladie de Parkinson | Parkinson | Parkinson-kór | Parkinsonova bolezen | 帕金森病 | ICD-11 nervous system |
| C041 | HEALTH | migraine | migraine | migraine | migrén | migrena | 偏头痛 | ICD-11 nervous system |
| C042 | HEALTH | stroke | AVC | beroerte | agyvérzés | možganska kap | 中风 | ICD-11 nervous system |
| C043 | HEALTH | chronic pain | douleur chronique | chroniese pyn | krónikus fájdalom | kronična bolečina | 慢性疼痛 | ICD-11 nervous system |
| C044 | HEALTH | hypertension | hypertension | hipertensie | magas vérnyomás | hipertenzija | 高血压 | ICD-11 circulatory |
| C045 | HEALTH | heart attack | infarctus | hartaanval | szívroham | srčni infarkt | 心肌梗死 | ICD-11 circulatory |
| C046 | HEALTH | heart failure | insuffisance cardiaque | hartversaking | szívelégtelenség | srčno popuščanje | 心力衰竭 | ICD-11 circulatory |
| C047 | HEALTH | angina | angine de poitrine | angina | angina pectoris | angina pektoris | 心绞痛 | ICD-11 circulatory |
| C048 | HEALTH | thrombosis | thrombose | trombose | trombózis | tromboza | 血栓形成 | ICD-11 circulatory |
| C049 | HEALTH | varicose veins | varices | aartjies | visszeres | krčne žile | 静脉曲张 | ICD-11 circulatory |
| C050 | HEALTH | asthma | asthme | asma | asztma | astma | 哮喘 | ICD-11 respiratory |
| C051 | HEALTH | COPD | BPCO | COPD | COPD | KOPB | 慢阻肺 | ICD-11 respiratory |
| C052 | HEALTH | tuberculosis | tuberculose | tuberkulose | tuberkulózis | tuberkuloza | 结核病 | ICD-11 infectious |
| C053 | HEALTH | pneumonia | pneumonie | longontsteking | tüdőgyulladás | pljučnica | 肺炎 | ICD-11 respiratory |
| C054 | HEALTH | HIV | VIH | MIV | HIV | HIV | 艾滋病毒 | ICD-11 infectious |
| C055 | HEALTH | AIDS | sida | VIGS | AIDS | AIDS | 艾滋病 | ICD-11 infectious |
| C056 | HEALTH | hepatitis | hépatite | hepatitis | hepatitis | hepatitis | 肝炎 | ICD-11 infectious |
| C057 | HEALTH | hepatitis B | hépatite B | hepatitis B | B-hepatitis | hepatitis B | 乙型肝炎 | ICD-11 infectious |
| C058 | HEALTH | hepatitis C | hépatite C | hepatitis C | C-hepatitis | hepatitis C | 丙型肝炎 | ICD-11 infectious |
| C059 | HEALTH | syphilis | syphilis | sifilis | szifilisz | sifilis | 梅毒 | ICD-11 infectious |
| C060 | HEALTH | chlamydia | chlamydia | chlamidia | chlamydia | klamidija | 衣原体感染 | ICD-11 infectious |
| C061 | HEALTH | herpes | herpès | herpes | herpesz | herpes | 疱疹 | ICD-11 infectious |
| C062 | HEALTH | influenza | grippe | griep | influenza | gripa | 流感 | ICD-11 infectious |
| C063 | HEALTH | measles | rougeole | masels | kanyaró | ošpice | 麻疹 | ICD-11 infectious |
| C064 | HEALTH | COVID-19 | covid-19 | covid-19 | covid-19 | covid-19 | 新冠肺炎 | ICD-11 infectious |
| C065 | HEALTH | long COVID | covid long | lang covid | hosszú covid | dolgi covid | 长期新冠 | ICD-11 infectious |
| C066 | HEALTH | sepsis | sepsis | sepsis | szepszis | sepsa | 败血症 | ICD-11 infectious |
| C067 | HEALTH | meningitis | méningite | meningitis | agyhártyagyulladás | meningitis | 脑膜炎 | ICD-11 nervous system |
| C068 | HEALTH | Crohn | maladie de Crohn | Crohn | Crohn-betegség | Crohnova bolezen | 克罗恩病 | ICD-11 digestive |
| C069 | HEALTH | cirrhosis | cirrhose | siroos | májcirrhózis | ciroza | 肝硬化 | ICD-11 digestive |
| C070 | HEALTH | coeliac disease | maladie cœliaque | coeliakie | cöliákia | celiakija | 乳糜泻 | ICD-11 digestive |
| C071 | HEALTH | peptic ulcer | ulcère | maagsweer | fekély | razjeda | 溃疡 | ICD-11 digestive |
| C072 | HEALTH | gallstones | calculs biliaires | galstene | epekkő | žolčni kamni | 胆结石 | ICD-11 digestive |
| C073 | HEALTH | kidney stones | calculs rénaux | niersteentjies | vesekő | ledvični kamni | 肾结石 | ICD-11 genitourinary |
| C074 | HEALTH | hernia | hernie | hernia | sérv | kila | 疝气 | ICD-11 digestive |
| C075 | HEALTH | arthritis | arthrite | artritis | ízületi gyulladás | artritis | 关节炎 | ICD-11 musculoskeletal |
| C076 | HEALTH | osteoporosis | ostéoporose | osteoporose | csontritkulás | osteoporoza | 骨质疏松症 | ICD-11 musculoskeletal |
| C077 | HEALTH | sciatica | sciatique | iskias | ischias | ishias | 坐骨神经痛 | ICD-11 musculoskeletal |
| C078 | HEALTH | scoliosis | scoliose | skoliose | gerincferdülés | skolioza | 脊柱侧弯 | ICD-11 musculoskeletal |
| C079 | HEALTH | lupus | lupus | lupus | lupus | lupus | 红斑狼疮 | ICD-11 musculoskeletal |
| C080 | HEALTH | psoriasis | psoriasis | psoriasis | pszoriázis | luskavec | 银屑病 | ICD-11 skin |
| C081 | HEALTH | eczema | eczéma | ekseem | ekcéma | ekcem | 湿疹 | ICD-11 skin |
| C082 | HEALTH | vitiligo | vitiligo | vitiligo | vitiligó | vitiligo | 白癜风 | ICD-11 skin |
| C083 | HEALTH | pregnancy | grossesse | swangerskap | terhesség | nosečnost | 怀孕 | ICD-11 pregnancy |
| C084 | HEALTH | miscarriage | fausse couche | miskraam | vetélés | spontani abortus | 流产 | ICD-11 pregnancy |
| C085 | HEALTH | abortion | avortement | aborsie | abortusz | abortus | 堕胎 | ICD-11 pregnancy |
| C086 | HEALTH | infertility | infertilité | onvrugbaarheid | meddőség | neplodnost | 不孕 | ICD-11 genitourinary |
| C087 | HEALTH | IVF | FIV | IVF | IVF | IVF | 试管婴儿 | ICD-11 factors influencing health |
| C088 | HEALTH | childbirth | accouchement | bevalling | szülés | porod | 分娩 | ICD-11 pregnancy |
| C089 | HEALTH | glaucoma | glaucome | glourkoom | glaukóma | glavkom | 青光眼 | ICD-11 visual system |
| C090 | HEALTH | cataract | cataracte | katarak | szürkehályog | katarakta | 白内障 | ICD-11 visual system |
| C091 | HEALTH | deafness | surdité | doofheid | süketség | gluhost | 耳聋 | ICD-11 ear |
| C092 | HEALTH | kidney disease | maladie rénale | nierfunksieversteuring | veseelégtelenség | ledvična bolezen | 肾病 | ICD-11 genitourinary |
| C093 | HEALTH | dialysis | dialyse | dialise | dialízis | dializa | 透析 | ICD-11 genitourinary |
| C094 | HEALTH | disability | handicap | gestremdheid | fogyatékosság | invalidnost | 残疾 | ICD-11 factors influencing health |
| C095 | HEALTH | chronic illness | maladie chronique | chroniese siekte | krónikus betegség | kronična bolezen | 慢性病 | ICD-11 factors influencing health |
| C096 | HEALTH | chronic fatigue | fatigue chronique | chroniese moegheid | krónikus fáradtság | kronična utrujenost | 慢性疲劳 | ICD-11 nervous system |
| C097 | HEALTH | Down syndrome | trisomie | Down-sindroom | Down-szindróma | Downov sindrom | 唐氏综合征 | ICD-11 congenital |
| C098 | HEALTH | cerebral palsy | paralysie cérébrale | serebrale gestremdheid | agyi bénulás | cerebralna paraliza | 脑瘫 | ICD-11 nervous system |
| C099 | HEALTH | anaphylaxis | anaphylaxie | anafilaksie | anafilaxia | anafilaksija | 过敏性休克 | ICD-11 immune system |
| C100 | HEALTH | allergy | allergie | allergie | allergia | alergija | 过敏 | ICD-11 immune system |
| C101 | HEALTH | anaemia | anémie | bloedarmoede | vérszegénység | anemija | 贫血 | ICD-11 blood |
| C102 | HEALTH | hypothyroidism | hypothyroïdie | hipotiroïdie | pajzsmirigy-alulműködés | hipotiroidizem | 甲状腺功能减退 | ICD-11 endocrine |
| C103 | HEALTH | hyperthyroidism | hyperthyroïdie | hipertiroïdie | pajzsmirigy-túlműködés | hipertiroidizem | 甲状腺功能亢进 | ICD-11 endocrine |
| C104 | HEALTH | pancreatitis | pancréatite | pankreatitis | hasnyálmirigy-gyulladás | pankreatitis | 胰腺炎 | ICD-11 digestive |
| C105 | HEALTH | sick leave | arrêt maladie | siekverlof | táppénz | bolniška odsotnost | 病假 | administrative (health) |
| C106 | HEALTH | medical certificate | certificat médical | mediese sertifikaat | orvosi igazolás | zdravniško potrdilo | 医疗证明 | administrative (health) |
| C107 | HEALTH | medical record | dossier médical | mediese rekord | kórlap | zdravstveni karton | 病历 | administrative (health) |
| C108 | HEALTH | hospitalisation | hospitalisation | hospitalisering | kórházi kezelés | hospitalizacija | 住院 | administrative (health) |
| C109 | HEALTH | mental health | santé mentale | geestesgesondheid | mentális egészség | duševno zdravje | 心理健康 | ICD-11 factors influencing health |
| C110 | HEALTH | mental illness | maladie mentale | geestesversteuring | mentális betegség | duševna bolezen | 精神疾病 | ICD-11 mental disorders |
| C111 | HEALTH | psychosis | psychose | psigose | pszichózis | psihoza | 精神病 | ICD-11 mental disorders |
| C112 | HEALTH | bipolar | bipolaire | bipolêre | bipoláris | bipolarno | 双相 | ICD-11 mental disorders |
| C113 | HEALTH | cancerous | cancéreux | kankeragtig | rákos | rakav | 癌性的 | ICD-11 neoplasms |
| C114 | HEALTH | depressed | déprimé | depressief | depressziós | depresiven | 抑郁的 | ICD-11 mental disorders |
| C115 | HEALTH | abortion pill | pilule abortive | aborsiepil | abortuszpirula | abortivna tableta | 堕胎药 | ICD-11 pregnancy |

## Drugs (psychiatric, HIV and oncology)

Each name is language-neutral (lang `xx`). The brand names are the product names
of common medicines; the INN names are WHO INN names.

| id | class | name | source |
|---|---|---|---|
| D001 | antidepressant | fluoxetine | WHO INN |
| D002 | antidepressant | sertraline | WHO INN |
| D003 | antidepressant | citalopram | WHO INN |
| D004 | antidepressant | escitalopram | WHO INN |
| D005 | antidepressant | paroxetine | WHO INN |
| D006 | antidepressant | venlafaxine | WHO INN |
| D007 | antidepressant | duloxetine | WHO INN |
| D008 | antidepressant | mirtazapine | WHO INN |
| D009 | antidepressant | amitriptyline | WHO INN |
| D010 | antipsychotic | quetiapine | WHO INN |
| D011 | antipsychotic | risperidone | WHO INN |
| D012 | antipsychotic | olanzapine | WHO INN |
| D013 | antipsychotic | aripiprazole | WHO INN |
| D014 | antipsychotic | clozapine | WHO INN |
| D015 | antipsychotic | haloperidol | WHO INN |
| D016 | anxiolytic | lorazepam | WHO INN |
| D017 | anxiolytic | diazepam | WHO INN |
| D018 | anxiolytic | alprazolam | WHO INN |
| D019 | anxiolytic | oxazepam | WHO INN |
| D020 | ADHD stimulant | methylphenidate | WHO INN |
| D021 | HIV | tenofovir | WHO INN |
| D022 | HIV | emtricitabine | WHO INN |
| D023 | HIV | dolutegravir | WHO INN |
| D024 | HIV | bictegravir | WHO INN |
| D025 | HIV | efavirenz | WHO INN |
| D026 | HIV | lamivudine | WHO INN |
| D027 | HIV | zidovudine | WHO INN |
| D028 | HIV | abacavir | WHO INN |
| D029 | HIV | raltegravir | WHO INN |
| D030 | HIV | darunavir | WHO INN |
| D031 | HIV | cabotegravir | WHO INN |
| D032 | HIV | rilpivirine | WHO INN |
| D033 | oncology | tamoxifen | WHO INN |
| D034 | oncology | letrozole | WHO INN |
| D035 | oncology | anastrozole | WHO INN |
| D036 | oncology | imatinib | WHO INN |
| D037 | oncology | trastuzumab | WHO INN |
| D038 | oncology | rituximab | WHO INN |
| D039 | oncology | bevacizumab | WHO INN |
| D040 | oncology | cisplatin | WHO INN |
| D041 | oncology | paclitaxel | WHO INN |
| D042 | oncology | capecitabine | WHO INN |
| D043 | brand | Prozac | brand |
| D044 | brand | Zoloft | brand |
| D045 | brand | Xanax | brand |
| D046 | brand | Valium | brand |
| D047 | brand | Seroquel | brand |
| D048 | brand | Risperdal | brand |
| D049 | brand | Abilify | brand |
| D050 | brand | Ritalin | brand |
| D051 | brand | Lexapro | brand |
| D052 | brand | Lexomil | brand |
| D053 | brand | Truvada | brand |
| D054 | brand | Descovy | brand |
| D055 | brand | Biktarvy | brand |
| D056 | brand | Triumeq | brand |
| D057 | brand | Tivicay | brand |
| D058 | brand | Genvoya | brand |

## Art. 9 categories

| id | category | EN | FR | AF | HU | SL | ZH | source |
|---|---|---|---|---|---|---|---|---|
| A002 | RELIGION | Muslim | musulman | moslem | muszlim | musliman | 穆斯林 | GDPR Art. 9 |
| A003 | RELIGION | Jewish | juif | jood | zsidó | judovsk | 犹太人 | GDPR Art. 9 |
| A004 | RELIGION | Catholic | catholique | katoliek | katolikus | katoliški | 天主教徒 | GDPR Art. 9 |
| A005 | RELIGION | Protestant | protestant | protestant | református | protestant | 新教徒 | GDPR Art. 9 |
| A006 | RELIGION | Buddhist | bouddhiste | boeddhis | buddhista | budist | 佛教徒 | GDPR Art. 9 |
| A007 | RELIGION | Hindu | hindou | hindoe | hindu | hindu | 印度教徒 | GDPR Art. 9 |
| A008 | RELIGION | Sikh | sikh | sikh | szikh | sikh | 锡克教徒 | GDPR Art. 9 |
| A009 | SEXUAL_ORIENTATION | homosexual | homosexuel | homoseksueel | homoszexuális | homoseksualen | 同性恋 | GDPR Art. 9 |
| A010 | SEXUAL_ORIENTATION | bisexual | bisexuel | biseksueel | biszexuális | biseksualen | 双性恋 | GDPR Art. 9 |
| A011 | SEXUAL_ORIENTATION | lesbian | lesbienne | lesbies | leszbikus | lezbijka | 女同性恋 | GDPR Art. 9 |
| A012 | SEXUAL_ORIENTATION | transgender | transgenre | transgender | transzneműs | transspolna oseba | 跨性别 | GDPR Art. 9 |
| A013 | TRADE_UNION | trade union member | syndiqué | vakbondslid | szakszervezeti tag | sindikalni član | 工会会员 | GDPR Art. 9 |
| A014 | ETHNIC_ORIGIN | ethnic origin | origine ethnique | etniese herkoms | etnikai származás | etnično poreklo | 民族出身 | GDPR Art. 9 |
| A015 | ETHNIC_ORIGIN | racial origin | origine raciale | rassehuidskleur | faji származás | rasno poreklo | 种族出身 | GDPR Art. 9 |
