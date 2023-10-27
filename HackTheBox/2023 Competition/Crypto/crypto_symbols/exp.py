from Crypto.Util.number import *
from sage.all import *
from tqdm import trange

ct = [236195756868517656723513582436861606906, 57834783484301373179714799552205481954, 267720308275932715147205375538382826955, 149092033205073279855511853881589809010, 58424761794072998702558565907923210061, 1474110831190262608109442199483811396, 163053413501521220432813224719322520343, 119823699155184027043969102805062191441, 159571890149858495555307399445325012284, 195717201450729986508861286257046392334, 114431778290475226872809734457174018792, 218162028253871849172261202156083591640, 109672631939007910803691571069172981811, 193433512850089598853923720218322897666, 203707553307882002060636523391132788830, 165178305100165779779082572019143752076, 168112790210921765812613688558600521933, 259295183477837074170544386397411962537, 72159425377499728967395838521170265678, 61257639550003930626655558573570375667, 53912044472574402035294330397655014508, 226759619237657768020688997684351249522, 207669219042336576373060372576522188926, 62218709641327619861361701519347901903, 221930182162000427234878462314905615934, 103905100137359639759778538644836993114, 122085512968076140186478249097034194620, 79790132810657519260425461575563651014, 105720237588559999443513176173321207812, 4141874793962506085501192334821873588, 258260700143946447861527599261604556990, 304836041323039503483423294942352823225, 74711472409612511216985339518022873265, 281293548316789520771629451289333366059, 33315385586376261091605566022845019165, 195031151608254832747861469332299766779, 8874453320499641503217809067221226651, 218372886049824560689090550490862269745, 49443672021619856243541967231484922934, 3797928589787299936105903884032628983, 233232957701005845474826605663076782322, 225717577262646644076173305131793012952, 217674854438450569168330544830834890239, 112632127397310466151290839212576069250, 297054153782140787762508061528667326334, 200864923363562552986304896619830418825, 207814447965726601601459303467914840668, 183268898499264583001015073048851916267, 302323867260523032831652951482239931870, 121811779197657018566930567987706650145, 197939160714477105354408139112513818588, 242467408311754766994790469368889328898, 125047863006239061494525332911274359824, 256055239004494720079913801004332470083, 125481538676534939361509260427893757231, 151961354577514699876702118550614978524, 139337233502703760972938620054847414082, 54273025797683328748801507686107401875, 20653194921403421700512039686521584608, 4016737468201962410736344683218936054, 89329187741361387359560746315142203118, 225406976281509920555422230168821297298, 191990134569339659970088329840165511825, 230851829782994261833309017999787924324, 116560901475560555203390303370847962630, 242922874400477413665861083227177676592, 158273966342641837379946400042003253821, 192463194708815919706398960822785854561, 88590986965981017167863091396039010259, 125699959791975424231829606670777297509, 4674062135079405678161986278960978859, 295915697039920278742246054056568248046, 153777500463526326680976578455362797868, 293641984445847968623799820749440556400, 278260155507943247430558495672029343269, 116970199964828316399106934265923277177, 141314664087726853403505171598611919153, 249880828871252544637608762004255492665, 75397135144827510989108863721550837615, 25838141974541593100207855375396418337, 26744542605064423411838425224569882883, 111479658873107426450034025232787393071, 122711549557000570999859254230225985996, 234452168130798426103090678301960430088, 83344563444820883307048423914760857323, 285842052907810469311410015384329848393, 191261144309106677852390682025226532253, 78694100597213810147271333579864536178, 173848085329452212926926348067495134194, 64022993630438250686170301246585182721, 63009085631787857429160386034458198051, 32480634537935362268355670906886932080, 15767933517959013175137111051917516119, 71366103925656507820659219493116240126, 101691033666002415795570133186208824977, 69077658268707695484939357549270516417, 198008703086408244773830406047222547556, 237395086066778758585182789083839256019, 205904022862678237509786919700364500959, 93211126636702829233154574509713589989, 256772439038083190309486076111014772656, 117571035407272577532112292917924278022, 136565134972912087872852453761091589160, 302903980502928774842775159472377670659, 298208918278247203432422660467294890950, 247097638235639481178843100500741237318, 134638530165023910128750529207711830960, 296279440176443131848519174817772138477, 165607260838070337290216988963065657083, 54911438888497322338109298177844240543, 168091545668922619001185882538771831439, 12215198757054277945398872885469039147, 122780515235756935579877715051906605546, 227020386677629300158182259879513885762, 74128308616899714992851545962325008402, 202563904115494462045595239113178641323, 149831878127553695987542192078256701710, 238152846378867475824845759737563349039, 278975537557617527678850286807410984472, 62613765016341084522786354050558351860, 296416498974660277931027536134376948346, 298156951068506317844513484521568851490, 184857979739230402610346646714463615285, 18215115330156213991963479735615174612, 246575730483301894676542218420556342453, 288099039376805825533003504758225360291, 191480423471330209234209054269123597554, 71084901912387674608479851321519928803, 45025071362222616113441090389072097071, 47620844975568098051343557505789982861, 298988967095500526924406670118972931260, 274276110781743436003951153676720478208, 130051356372257282201920118270791087716, 168916731432425112528932729279316481951, 225007381772166558729133871780815889731, 19725433433059362390974491854784109938, 255915832194239778048105829254853414726, 6644537965927963748198410436363467288, 163097611704424430946284387974035660349, 48389408225757261676459402198619415601, 61532562092874334447628732019654365804, 257755096243341069093312281254996172530, 247936228891023955947779262224689661380, 37224790653696805486661551965348336941, 89025744901662857405455718528011117409, 60327330352788361126613658737898278840, 74344193034206774178892060428966116376, 99784993351916151851963129920650514530, 152791116215170114868237524767153153802, 121338741590551548864430726541831702247, 30438637110699532867010569930825901434, 221617393582282874954397442060287758793, 14335452200619389704697216360554150486, 266995951927721576787062579738384941652, 281343126394302164903102667378494617352, 16739553438865022310592036238508977330, 253605084816117830134213395574634463053, 17384228471503215307237391182318780430, 216055509119502048997741680911789269797, 184507338305919388856283781529498633535, 51389227945438052497410296595640795704, 182500594593682723835476489937944895338, 85313866949219500557954565524206618756, 255933139989091469559877467758030327253, 204221676677881668915398948904684105139, 201886330940557766757109782145016304770, 63727781773389659124509558143155049119, 164577570238479135052249983309370554778, 115887181697954014087831883275734193081, 257076910446287373230455041235610692953, 208246011947463918290284535660262795719, 307105846442992112962542896686899770051, 121976208912564964708698710006201593571, 163461558927216486634752210087176402455, 290519313398890946595778740210070336240, 39203578724350145282500607866944398967, 36523367157502206102320447880131433844, 239158505405518099010344289063727310109, 243068194421293287816921280815087141790, 115947026056914530480508458123557660006, 80361565875364590423052169473490309212, 228007972455330275193466018159013433399, 134878085638954763841868802087259023596, 126591485019910341476262982620391507528, 118018557764442719612409042878868887697, 175147784961440782032159796888417850042, 96604741734837402795929961836428550283, 115232088396576913784926728654494159155, 106844211943253380430858231501962723551, 63724090034639938418527698826192190939, 183267820914390636517030558110527813450, 139481782792347806645625197109286281120, 121824936515060660633139132885887499509, 8711110773158345810088636822685682128, 124698954991793872069705307233086457583, 164245012941658709485225086084374233148, 157399147837313309316589350353131069565, 12780681122629277316433056617016959595, 209378556853742644514050481232965095819, 25507075573308575203960763012617360890, 286351492453862354434326436861658392289, 36558436246048335181380188335192579745, 248219506497737852157148440403355874294, 167052573917454348660976630103224461763, 287742508661132192679080142777326943078, 214739677620109734459757547397409471726, 43519490587480378265122136825365148297, 264055517464798835137048684481896521027, 184326284522391984806573933461104011431, 44312092754397009855216164718045393529, 264119759594177981502747517417334293096, 231414584115935009145680519630602573691, 172539931164133296022607545277616306205, 250790905503673347740179537105576289757, 100585924827282275356136738210910608317, 291175888026300278788944252184398225125, 123696827599086998573981831183879350990, 2714736006483713948364807805417050020, 88733050593640685036147902835072291514, 245949917889787416890372591178866160759, 149705592266286677351645289140172981365, 230528475189017384850586421963905015996, 3099453341705819769647982816039023583, 205601700086886362121938960970307872784, 3198233509586496931157640450973851894, 303359660981657618955290356323663714981, 53080026997598326189063046677156042263, 12714480048192740511666984652343564346, 212888039401798018228261148638975121006, 248923232574268778482155483906179481919, 9200775760650755894188275376278954956, 42907096522449491990857339940972309324, 235480951988870887019575287286880601264, 293133213198426097957882572248927314596, 196832033324586505625417235977142479515, 122705993887041956554246104507107895409, 108930112678453882813097048888517740026, 228759717969465092631433676028477838418, 304220599780001881438247991395753464783, 247699159660177899954351863795037449427, 275954641831049011183199826362274348150, 62235924022379692600390452595282611159, 153964122875902668860592613490799863065, 7344457580103426721894059292348121307, 138129528902400549074393680724652685460, 159315655303173638975535262737876992270, 69693847123803815575660789144207379006, 298099532115413882220744068548490459339, 205862690430932330159215811046997635726, 96317282826485586400864298654644481887, 23937935386088941151058501310619472716, 145947278542188427028262512698338375558, 267452453646135270741219728053170391028, 288777494479956244519361188932901789376, 189007828638707729316967591964525836716, 234999483132413547429813569972270710947, 96818691916198330670623725451046553945, 215934053902817601850452667648128844911, 274463243428737114462024956225263986236, 31511281927617313382900876235136549967, 262766372668962845198793862636348799289, 14300182111226453525099656894243318562, 157479395673257614656221512912298657316, 89722147804475163613425581258122084223, 10537630147990422486988159119205807485, 43905505729292249543997847489728001109, 249022795202149221294807001666358809127, 280991707374757320685631136221711018424, 9334192016863140524107799111418272158, 102542812213063790129052110380749499250, 33375019399194492081238475705898606539, 230108062771962518992670788864093732153, 38971363207231658575341873575053872898, 252735959260023414878941933950360223528, 99437350362178867106495056411160140892, 261273561464335304223117862121010299160, 51893977578780771348561944270086680742, 134947265937359026966137347794039001160, 261879558177400947692509741360573074954]
p = 307163712384204009961137975465657319439
g = Mod(1337, p)


# flag = ""

# for i in trange(len(ct)):
#     r = discrete_log(ct[i], g)
#     if r % 2 == 1:
#         flag += '1'
#     else:
#         flag += '0'

# print(long_to_bytes(int(flag, 2)).decode("cp437"))

def PohligHellman(g,h,p):
    pretty_print(html('The prime $p$ is $%s$'%latex(p)))
    F=GF(p)
    g1=F(g)
    h1=F(h)
    N=p-1
    print(N)
    qi=[r^N.valuation(r) for r in prime_divisors(N)]
    pretty_print(html('Prime power divisors of $p-1: %s$'%latex(qi)))
    lqi=len(qi)
    Nqi=[N/q for q in qi]
    gi=[g1^r for r in Nqi]
    hi=[h1^r for r in Nqi]
    xi=[discrete_log(hi[i],gi[i]) for i in range(lqi)]
    pretty_print(html('Discrete logarithms $x_i=%s$'%latex(xi)))
    x=CRT(xi,qi)
    pretty_print(html(r'We have that $\log_g h=%s$'%latex(x)))
    return x
p = 307163712384204009961137975465657319439
g = 1337
ct = [236195756868517656723513582436861606906, 57834783484301373179714799552205481954, 267720308275932715147205375538382826955, 149092033205073279855511853881589809010, 58424761794072998702558565907923210061, 1474110831190262608109442199483811396, 163053413501521220432813224719322520343, 119823699155184027043969102805062191441, 159571890149858495555307399445325012284, 195717201450729986508861286257046392334, 114431778290475226872809734457174018792, 218162028253871849172261202156083591640, 109672631939007910803691571069172981811, 193433512850089598853923720218322897666, 203707553307882002060636523391132788830, 165178305100165779779082572019143752076, 168112790210921765812613688558600521933, 259295183477837074170544386397411962537, 72159425377499728967395838521170265678, 61257639550003930626655558573570375667, 53912044472574402035294330397655014508, 226759619237657768020688997684351249522, 207669219042336576373060372576522188926, 62218709641327619861361701519347901903, 221930182162000427234878462314905615934, 103905100137359639759778538644836993114, 122085512968076140186478249097034194620, 79790132810657519260425461575563651014, 105720237588559999443513176173321207812, 4141874793962506085501192334821873588, 258260700143946447861527599261604556990, 304836041323039503483423294942352823225, 74711472409612511216985339518022873265, 281293548316789520771629451289333366059, 33315385586376261091605566022845019165, 195031151608254832747861469332299766779, 8874453320499641503217809067221226651, 218372886049824560689090550490862269745, 49443672021619856243541967231484922934, 3797928589787299936105903884032628983, 233232957701005845474826605663076782322, 225717577262646644076173305131793012952, 217674854438450569168330544830834890239, 112632127397310466151290839212576069250, 297054153782140787762508061528667326334, 200864923363562552986304896619830418825, 207814447965726601601459303467914840668, 183268898499264583001015073048851916267, 302323867260523032831652951482239931870, 121811779197657018566930567987706650145, 197939160714477105354408139112513818588, 242467408311754766994790469368889328898, 125047863006239061494525332911274359824, 256055239004494720079913801004332470083, 125481538676534939361509260427893757231, 151961354577514699876702118550614978524, 139337233502703760972938620054847414082, 54273025797683328748801507686107401875, 20653194921403421700512039686521584608, 4016737468201962410736344683218936054, 89329187741361387359560746315142203118, 225406976281509920555422230168821297298, 191990134569339659970088329840165511825, 230851829782994261833309017999787924324, 116560901475560555203390303370847962630, 242922874400477413665861083227177676592, 158273966342641837379946400042003253821, 192463194708815919706398960822785854561, 88590986965981017167863091396039010259, 125699959791975424231829606670777297509, 4674062135079405678161986278960978859, 295915697039920278742246054056568248046, 153777500463526326680976578455362797868, 293641984445847968623799820749440556400, 278260155507943247430558495672029343269, 116970199964828316399106934265923277177, 141314664087726853403505171598611919153, 249880828871252544637608762004255492665, 75397135144827510989108863721550837615, 25838141974541593100207855375396418337, 26744542605064423411838425224569882883, 111479658873107426450034025232787393071, 122711549557000570999859254230225985996, 234452168130798426103090678301960430088, 83344563444820883307048423914760857323, 285842052907810469311410015384329848393, 191261144309106677852390682025226532253, 78694100597213810147271333579864536178, 173848085329452212926926348067495134194, 64022993630438250686170301246585182721, 63009085631787857429160386034458198051, 32480634537935362268355670906886932080, 15767933517959013175137111051917516119, 71366103925656507820659219493116240126, 101691033666002415795570133186208824977, 69077658268707695484939357549270516417, 198008703086408244773830406047222547556, 237395086066778758585182789083839256019, 205904022862678237509786919700364500959, 93211126636702829233154574509713589989, 256772439038083190309486076111014772656, 117571035407272577532112292917924278022, 136565134972912087872852453761091589160, 302903980502928774842775159472377670659, 298208918278247203432422660467294890950, 247097638235639481178843100500741237318, 134638530165023910128750529207711830960, 296279440176443131848519174817772138477, 165607260838070337290216988963065657083, 54911438888497322338109298177844240543, 168091545668922619001185882538771831439, 12215198757054277945398872885469039147, 122780515235756935579877715051906605546, 227020386677629300158182259879513885762, 74128308616899714992851545962325008402, 202563904115494462045595239113178641323, 149831878127553695987542192078256701710, 238152846378867475824845759737563349039, 278975537557617527678850286807410984472, 62613765016341084522786354050558351860, 296416498974660277931027536134376948346, 298156951068506317844513484521568851490, 184857979739230402610346646714463615285, 18215115330156213991963479735615174612, 246575730483301894676542218420556342453, 288099039376805825533003504758225360291, 191480423471330209234209054269123597554, 71084901912387674608479851321519928803, 45025071362222616113441090389072097071, 47620844975568098051343557505789982861, 298988967095500526924406670118972931260, 274276110781743436003951153676720478208, 130051356372257282201920118270791087716, 168916731432425112528932729279316481951, 225007381772166558729133871780815889731, 19725433433059362390974491854784109938, 255915832194239778048105829254853414726, 6644537965927963748198410436363467288, 163097611704424430946284387974035660349, 48389408225757261676459402198619415601, 61532562092874334447628732019654365804, 257755096243341069093312281254996172530, 247936228891023955947779262224689661380, 37224790653696805486661551965348336941, 89025744901662857405455718528011117409, 60327330352788361126613658737898278840, 74344193034206774178892060428966116376, 99784993351916151851963129920650514530, 152791116215170114868237524767153153802, 121338741590551548864430726541831702247, 30438637110699532867010569930825901434, 221617393582282874954397442060287758793, 14335452200619389704697216360554150486, 266995951927721576787062579738384941652, 281343126394302164903102667378494617352, 16739553438865022310592036238508977330, 253605084816117830134213395574634463053, 17384228471503215307237391182318780430, 216055509119502048997741680911789269797, 184507338305919388856283781529498633535, 51389227945438052497410296595640795704, 182500594593682723835476489937944895338, 85313866949219500557954565524206618756, 255933139989091469559877467758030327253, 204221676677881668915398948904684105139, 201886330940557766757109782145016304770, 63727781773389659124509558143155049119, 164577570238479135052249983309370554778, 115887181697954014087831883275734193081, 257076910446287373230455041235610692953, 208246011947463918290284535660262795719, 307105846442992112962542896686899770051, 121976208912564964708698710006201593571, 163461558927216486634752210087176402455, 290519313398890946595778740210070336240, 39203578724350145282500607866944398967, 36523367157502206102320447880131433844, 239158505405518099010344289063727310109, 243068194421293287816921280815087141790, 115947026056914530480508458123557660006, 80361565875364590423052169473490309212, 228007972455330275193466018159013433399, 134878085638954763841868802087259023596, 126591485019910341476262982620391507528, 118018557764442719612409042878868887697, 175147784961440782032159796888417850042, 96604741734837402795929961836428550283, 115232088396576913784926728654494159155, 106844211943253380430858231501962723551, 63724090034639938418527698826192190939, 183267820914390636517030558110527813450, 139481782792347806645625197109286281120, 121824936515060660633139132885887499509, 8711110773158345810088636822685682128, 124698954991793872069705307233086457583, 164245012941658709485225086084374233148, 157399147837313309316589350353131069565, 12780681122629277316433056617016959595, 209378556853742644514050481232965095819, 25507075573308575203960763012617360890, 286351492453862354434326436861658392289, 36558436246048335181380188335192579745, 248219506497737852157148440403355874294, 167052573917454348660976630103224461763, 287742508661132192679080142777326943078, 214739677620109734459757547397409471726, 43519490587480378265122136825365148297, 264055517464798835137048684481896521027, 184326284522391984806573933461104011431, 44312092754397009855216164718045393529, 264119759594177981502747517417334293096, 231414584115935009145680519630602573691, 172539931164133296022607545277616306205, 250790905503673347740179537105576289757, 100585924827282275356136738210910608317, 291175888026300278788944252184398225125, 123696827599086998573981831183879350990, 2714736006483713948364807805417050020, 88733050593640685036147902835072291514, 245949917889787416890372591178866160759, 149705592266286677351645289140172981365, 230528475189017384850586421963905015996, 3099453341705819769647982816039023583, 205601700086886362121938960970307872784, 3198233509586496931157640450973851894, 303359660981657618955290356323663714981, 53080026997598326189063046677156042263, 12714480048192740511666984652343564346, 212888039401798018228261148638975121006, 248923232574268778482155483906179481919, 9200775760650755894188275376278954956, 42907096522449491990857339940972309324, 235480951988870887019575287286880601264, 293133213198426097957882572248927314596, 196832033324586505625417235977142479515, 122705993887041956554246104507107895409, 108930112678453882813097048888517740026, 228759717969465092631433676028477838418, 304220599780001881438247991395753464783, 247699159660177899954351863795037449427, 275954641831049011183199826362274348150, 62235924022379692600390452595282611159, 153964122875902668860592613490799863065, 7344457580103426721894059292348121307, 138129528902400549074393680724652685460, 159315655303173638975535262737876992270, 69693847123803815575660789144207379006, 298099532115413882220744068548490459339, 205862690430932330159215811046997635726, 96317282826485586400864298654644481887, 23937935386088941151058501310619472716, 145947278542188427028262512698338375558, 267452453646135270741219728053170391028, 288777494479956244519361188932901789376, 189007828638707729316967591964525836716, 234999483132413547429813569972270710947, 96818691916198330670623725451046553945, 215934053902817601850452667648128844911, 274463243428737114462024956225263986236, 31511281927617313382900876235136549967, 262766372668962845198793862636348799289, 14300182111226453525099656894243318562, 157479395673257614656221512912298657316, 89722147804475163613425581258122084223, 10537630147990422486988159119205807485, 43905505729292249543997847489728001109, 249022795202149221294807001666358809127, 280991707374757320685631136221711018424, 9334192016863140524107799111418272158, 102542812213063790129052110380749499250, 33375019399194492081238475705898606539, 230108062771962518992670788864093732153, 38971363207231658575341873575053872898, 252735959260023414878941933950360223528, 99437350362178867106495056411160140892, 261273561464335304223117862121010299160, 51893977578780771348561944270086680742, 134947265937359026966137347794039001160, 261879558177400947692509741360573074954]

pt = []
for i in trange(len(ct)):
    pt.append(PohligHellman(g,ct[i],p))
    