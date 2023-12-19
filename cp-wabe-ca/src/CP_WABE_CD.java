import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.stream.Collectors;

class Su{
    public Element Fx;
    public int x;

    public Su(Element Fx, int x){
        this.Fx = Fx;
        this.x = x;
    }
}

public class CP_WABE_CD {

    public Element a = null;
    public Element b = null;

    public static byte[] hash(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-256");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static Element hash2(String content, Pairing bp) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-512");
        instance.update(content.getBytes());
        byte[] bytes = instance.digest();
        Element element = bp.getGT().newElementFromHash(bytes, 0, bytes.length).getImmutable();
        return element;
    }

    public static Element hash3(Element element, Pairing bp) throws NoSuchAlgorithmException {
        byte[] bytes = element.toBytes();
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(bytes);
        bytes = instance.digest();
        Element tag = bp.getZr().newElementFromHash(bytes, 0, bytes.length).getImmutable();
        return tag;
    }

    public static Element lagrange(int i, int[] S, int x, Pairing bp){
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for(int j : S){
            if(i!=j){
                Element numerator = xElement.sub(bp.getZr().newElement(j)).getImmutable();
                Element denominator = iElement.sub(bp.getZr().newElement(j)).getImmutable();
                res = res.mul(numerator.div(denominator)).getImmutable();
            }
        }
        return res;
    }

    public static void storeProperties(Properties prop, String filename){
        try(FileOutputStream fileOutputStream = new FileOutputStream(filename)){
            prop.store(fileOutputStream, null);
        }catch (IOException e){
            e.printStackTrace();
            System.out.println(filename+"save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadProperties(String filename){
        Properties properties = new Properties();
        try(FileInputStream fileInputStream = new FileInputStream(filename)){
            properties.load(fileInputStream);
        }catch (IOException e) {
            e.printStackTrace();
            System.out.println(filename+"load failed!");
            System.exit(-1);
        }
        return properties;
    }

    public static void Setup(String pairingPropertiesFileName, String mskFileName, String pkFileName){
        Pairing bp = PairingFactory.getPairing(pairingPropertiesFileName);

        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();
        Element theta = bp.getZr().newRandomElement().getImmutable();
        Element g = bp.getG1().newRandomElement().getImmutable();

        Element h = g.powZn(beta).getImmutable();
        Element egg_alpha = bp.pairing(g, g).powZn(alpha).getImmutable();
        //Element g_alpha = g.powZn(alpha).getImmutable();
        Element g_theta = g.powZn(theta).getImmutable();
        //Element egg_alpha_theta = bp.pairing(g_theta,g).powZn(alpha).getImmutable();

        Properties pk = new Properties();
        Properties msk = new Properties();

        pk.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pk.setProperty("h", Base64.getEncoder().withoutPadding().encodeToString(h.toBytes()));
        pk.setProperty("egg_alpha", Base64.getEncoder().withoutPadding().encodeToString(egg_alpha.toBytes()));
        //pk.setProperty("egg_alpha_theta", Base64.getEncoder().withoutPadding().encodeToString(egg_alpha_theta.toBytes()));

        msk.setProperty("beta", Base64.getEncoder().withoutPadding().encodeToString(beta.toBytes()));
        //msk.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));
        msk.setProperty("g_theta", Base64.getEncoder().withoutPadding().encodeToString(g_theta.toBytes()));
        msk.setProperty("alpha", Base64.getEncoder().withoutPadding().encodeToString(alpha.toBytes()));

        storeProperties(pk, pkFileName);
        storeProperties(msk, mskFileName);
    }

    public static void Encrypt(String pairingPropertiesFileName, String m, String pkFileName, Node[] accessTree,
                               String ctFileName, int[] level) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingPropertiesFileName);

        Properties pk = loadProperties(pkFileName);

        //Element egg_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("egg_alpha"))).getImmutable();
        Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("h"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("g"))).getImmutable();
        //Element egg_alpha_theta = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("egg_alpha_theta"))).getImmutable();
        Element egg_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("egg_alpha"))).getImmutable();

        //选取s作为秘密值加密，并在访问树中分享
        Element s = bp.getZr().newRandomElement().getImmutable();

        //加密M，并乘以附加项egg_alpha_s,其中alpha是主私钥元素，s是加密阶段选取的随机数
        Element M = bp.getGT().newElementFromBytes(m.getBytes()).getImmutable();
        //Element M = hash2(m, bp).getImmutable();
        //Element cv = M.mul(egg_alpha_theta.powZn(s)).getImmutable();
        Element cv = M.mul(egg_alpha.powZn(s)).getImmutable();

        //计算c用来与D做pairing，用来除以恢复树后得到的结果，从而消去加密附加项
        //Element c = h.powZn(s).getImmutable();
        Element c_ = g.powZn(s).getImmutable();
        accessTree[0].secretShare = s;
        AccessTree.nodeShare(accessTree, accessTree[0], bp);

        Properties ct = new Properties();

        for(Node node:accessTree){
            if(Arrays.stream(level).boxed().collect(Collectors.toList()).contains(node.index)){
                Element cv_i = g.powZn(node.secretShare).getImmutable();
                ct.setProperty("cv"+node.index, Base64.getEncoder().withoutPadding().encodeToString(cv_i.toBytes()));
            }
        }

        //对于树中的每个叶节点计算相应的值，用来与密钥中对应属性的组件做pairing
        for(int i=0;i<accessTree.length;i++){
            Node node = accessTree[i];
            if(node.isLeaf()){
                //为属性计算C_Y
                Element c_y = h.powZn(node.secretShare).getImmutable();
                //为属性计算C_Y'

                byte[] attr = hash(node.att);
                Element H = bp.getG1().newElementFromHash(attr, 0, attr.length).getImmutable();
                Element c_y_1 = H.powZn(node.secretShare).getImmutable();

                ct.setProperty("c_y"+node.att+node.index, Base64.getEncoder().withoutPadding().encodeToString(c_y.toBytes()));
                ct.setProperty("c_y_1"+node.att+node.index, Base64.getEncoder().withoutPadding().encodeToString(c_y_1.toBytes()));

                //计算属性权值
                if(node.weight>1){
                    for(int j=1;j<node.weight;j++){
                        Node node_i = accessTree[node.index+j];
                        byte[] attr_1 = hash(node_i.att);
                        Element H_1 = bp.getG1().newElementFromHash(attr, 0, attr.length).getImmutable();
                        Element c_y_i = h.powZn(node_i.secretShare).getImmutable();
                        Element c_y_i_1 = H.powZn(node_i.secretShare).getImmutable();
                        ct.setProperty("c_y"+node_i.att+node_i.index, Base64.getEncoder().withoutPadding().encodeToString(c_y_i.toBytes()));
                        ct.setProperty("c_y_1"+node_i.att+node_i.index, Base64.getEncoder().withoutPadding().encodeToString(c_y_i_1.toBytes()));
                        i++;
                    }
                }
            }
        }
        ct.setProperty("cv", Base64.getEncoder().withoutPadding().encodeToString(cv.toBytes()));
        ct.setProperty("c_", Base64.getEncoder().withoutPadding().encodeToString(c_.toBytes()));
        storeProperties(ct, ctFileName);
    }

    public static void KeyGen(String pairingPropertiesFileName, String skFileName, String pkFileName, String mskFileName,
                              String[] S) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingPropertiesFileName);

        Properties msk = loadProperties(mskFileName);
        Properties pk = loadProperties(pkFileName);

        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("g"))).getImmutable();
        Element beta = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(msk.getProperty("beta"))).getImmutable();
        Element alpha = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(msk.getProperty("alpha"))).getImmutable();
        Element g_theta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(msk.getProperty("g_theta"))).getImmutable();

        //选取随机数r作为密钥生成过程中的秘密值
        Element r = bp.getZr().newRandomElement().getImmutable();
        //计算D
        Element g_theta_r = g_theta.powZn(r).getImmutable();
        Element g_alpha = g.powZn(alpha).getImmutable();
        Element D = g_alpha.mul(g_theta_r).getImmutable();

        //对每个属性计算组件，用来与树中对应的叶子节点做pairing
        Properties sk = new Properties();
        for(String att : S){
            //为每个属性选取r_j
            Element r_s = bp.getZr().newRandomElement().getImmutable();
            //根据r_j计算每个属性的D_j和D_j'
            Element r_s_beta = r_s.div(beta).getImmutable();
            byte[] attr = hash(att);
            Element H = bp.getG1().newElementFromHash(attr, 0, attr.length).getImmutable();
            Element D_j = g_theta_r.powZn(beta.invert()).mul(H.powZn(r_s_beta)).getImmutable();
            Element D_j_1 = g.powZn(r_s).getImmutable();

            sk.setProperty("D_j"+att, Base64.getEncoder().withoutPadding().encodeToString(D_j.toBytes()));
            sk.setProperty("D_j_1"+att, Base64.getEncoder().withoutPadding().encodeToString(D_j_1.toBytes()));
        }
        sk.setProperty("D", Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
        storeProperties(sk, skFileName);
    }

    public static Element Decrypt(String pairingPropertiesFileName, String[] S,String skFileName, String ctFileName, Node[] accessTree){
        Pairing bp = PairingFactory.getPairing(pairingPropertiesFileName);

        Properties ct = loadProperties(ctFileName);
        Properties sk = loadProperties(skFileName);

        Element cv = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cv"))).getImmutable();
        Element C_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("c_"))).getImmutable();
        Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D"))).getImmutable();

        //计算C,D的pairing值用来消去密文附加项
        //Element egg_ce = bp.pairing(C_, E).getImmutable();
        Element egg_cd = bp.pairing(C_, D).getImmutable();

        for(int i=0;i<accessTree.length;i++){
            Node node = accessTree[i];
            if(node.isLeaf()){
                if(Arrays.asList(S).contains(node.att)){
                    //计算每个叶节点的pairing值
                    Element c_y = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("c_y"+node.att+node.index))).getImmutable();
                    Element D_j = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D_j"+node.att))).getImmutable();
                    Element c_y_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("c_y_1"+node.att+node.index))).getImmutable();
                    Element D_j_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D_j_1"+node.att))).getImmutable();

                    node.secretShare = bp.pairing(c_y, D_j).div(bp.pairing(c_y_1, D_j_1)).getImmutable();
                }
            }
        }

        boolean treeOk = AccessTree.nodeRecover(accessTree, accessTree[0], S, bp);

        if(treeOk){
            return cv.div(egg_cd.div(accessTree[0].secretShare)).getImmutable();
        }
        else {
            System.out.println("Can't recover the tree!");
            return null;
        }

    }

    public static Su Semi_Decrypt(String pairingPropertiesFileName, String[] S,String skFileName, String ctFileName,
                                    Node[] accessTree, int level, Element D_u){
        Pairing bp = PairingFactory.getPairing(pairingPropertiesFileName);

        Properties ct = loadProperties(ctFileName);
        Properties sk = loadProperties(skFileName);

        for(int i=0;i<accessTree.length;i++){
            Node node = accessTree[i];
            if(node.isLeaf()){
                if(Arrays.asList(S).contains(node.att)){
                    //计算每个叶节点的pairing值
                    Element c_y = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("c_y"+node.att+node.index))).getImmutable();
                    Element D_j = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D_j"+node.att))).getImmutable();
                    Element c_y_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("c_y_1"+node.att+node.index))).getImmutable();
                    Element D_j_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D_j_1"+node.att))).getImmutable();
                    node.secretShare = bp.pairing(c_y, D_j).div(bp.pairing(c_y_1, D_j_1)).getImmutable();
                }
            }
        }
        boolean treeOk = AccessTree.nodeRecover(accessTree, accessTree[level], S, bp);
        if(treeOk){
            Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D"))).getImmutable();
            Element cv_i = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cv"+accessTree[level].index))).getImmutable();
            Element share = bp.pairing(cv_i, D_u.div(D)).mul(accessTree[level].secretShare).getImmutable();
            Su su = new Su(share, accessTree[level].index);
            return su;
        }
        else {
            System.out.println("Can't recover the node ["+level+"]!");
            return null;
        }
    }

    public static Element ShareDecrypt(String pairingPropertiesFileName, String ctFileName, Su[] sus, Element D_u) throws NoSuchAlgorithmException {

        Pairing bp = PairingFactory.getPairing(pairingPropertiesFileName);

        Properties ct = loadProperties(ctFileName);

        Element cv = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cv"))).getImmutable();
        Element c_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("c_"))).getImmutable();
        Element egg_cd = bp.pairing(c_,D_u).getImmutable();

        //利用拉格朗日插值计算秘密附加项
        int[] share = new int[sus.length];
        for(int i=0;i<share.length;i++){
            share[i] = sus[i].x;
        }
        Element secret = bp.getGT().newOneElement().getImmutable();
        for(Su su : sus){
            Element delta = lagrange(su.x, share, 0, bp).getImmutable();
            secret = secret.mul(su.Fx.powZn(delta)).getImmutable();
        }
        return cv.mul(secret).div(egg_cd).getImmutable();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String dir = "data/CP_WABE_SD/";

        String pairingPropertiesFileName = "a.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String ctFilename = dir + "ct.properties";
        String suFileName = dir + "su.properties";

        Pairing bp = PairingFactory.getPairing(pairingPropertiesFileName);

        Node[] accessTree_0 = new Node[21];
        accessTree_0[0] = new Node(new int[]{3, 3}, new int[][]{{1}, {2}, {3}, {4, 5}}, 0);
        accessTree_0[1] = new Node(new int[]{5, 5}, new int[][]{{6}, {7}, {8}, {9}, {10}}, 1);
        accessTree_0[2] = new Node(new int[]{5, 5}, new int[][]{{11}, {12}, {13}, {14}, {15}}, 2);
        accessTree_0[3] = new Node(new int[]{5, 5}, new int[][]{{16}, {17}, {18}, {19}, {20}}, 3);
        accessTree_0[4] = new Node("S", 2, 4);
        accessTree_0[5] = new Node("S", 2, 5);
        accessTree_0[6] = new Node("A", 1, 6);
        accessTree_0[7] = new Node("B", 1, 7);
        accessTree_0[8] = new Node("C", 1, 8);
        accessTree_0[9] = new Node("D", 1, 9);
        accessTree_0[10] = new Node("E", 1, 10);
        accessTree_0[11] = new Node("F", 1, 11);
        accessTree_0[12] = new Node("G", 1, 12);
        accessTree_0[13] = new Node("H", 1, 13);
        accessTree_0[14] = new Node("I", 1, 14);
        accessTree_0[15] = new Node("J", 1, 15);
        accessTree_0[16] = new Node("K", 1, 16);
        accessTree_0[17] = new Node("L", 1, 17);
        accessTree_0[18] = new Node("M", 1, 18);
        accessTree_0[19] = new Node("N", 1, 19);
        accessTree_0[20] = new Node("O", 1, 20);
        int[] level_0 = {1,2,3};
        Su[] sus_0 = new Su[3];
        String[] S0_0 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_0 = {{"A", "B", "C", "D", "E"}, {"F", "G", "H", "I", "J"}, {"K", "L", "M", "N", "O"}};

        Node[] accessTree_1 = new Node[25];
        accessTree_1[0] = new Node(new int[]{5, 5}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6, 7, 8, 9}}, 0);
        accessTree_1[1] = new Node(new int[]{3, 3}, new int[][]{{10}, {11}, {12}}, 1);
        accessTree_1[2] = new Node(new int[]{3, 3}, new int[][]{{13}, {14}, {15}}, 2);
        accessTree_1[3] = new Node(new int[]{3, 3}, new int[][]{{16}, {17}, {18}}, 3);
        accessTree_1[4] = new Node(new int[]{3, 3}, new int[][]{{19}, {20}, {21}}, 4);
        accessTree_1[5] = new Node(new int[]{3, 3}, new int[][]{{22}, {23}, {24}}, 5);
        accessTree_1[6] = new Node("S", 4, 6);
        accessTree_1[7] = new Node("S", 4, 7);
        accessTree_1[8] = new Node("S", 4, 8);
        accessTree_1[9] = new Node("S", 4, 9);
        accessTree_1[10] = new Node("A", 1, 10);
        accessTree_1[11] = new Node("B", 1, 11);
        accessTree_1[12] = new Node("C", 1, 12);
        accessTree_1[13] = new Node("D", 1, 13);
        accessTree_1[14] = new Node("E", 1, 14);
        accessTree_1[15] = new Node("F", 1, 15);
        accessTree_1[16] = new Node("G", 1, 16);
        accessTree_1[17] = new Node("H", 1, 17);
        accessTree_1[18] = new Node("I", 1, 18);
        accessTree_1[19] = new Node("J", 1, 19);
        accessTree_1[20] = new Node("K", 1, 20);
        accessTree_1[21] = new Node("L", 1, 21);
        accessTree_1[22] = new Node("M", 1, 22);
        accessTree_1[23] = new Node("N", 1, 23);
        accessTree_1[24] = new Node("O", 1, 24);
        int[] level_1 = {1, 2, 3, 4, 5};
        Su[] sus_1 = new Su[5];
        String[] S0_1 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_1 = {{"A", "B", "C"}, {"D", "E", "F"}, {"G", "H", "I"}, {"J", "K", "L"}, {"M", "N", "O"}};

        Node[] accessTree_2 = new Node[29];
        accessTree_2[0] = new Node(new int[]{7, 7}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8,9,10,11,12,13}}, 0);
        accessTree_2[1] = new Node(new int[]{2, 2}, new int[][]{{14}, {15}}, 1);
        accessTree_2[2] = new Node(new int[]{2, 2}, new int[][]{{16}, {17}}, 2);
        accessTree_2[3] = new Node(new int[]{2, 2}, new int[][]{{18}, {19}}, 3);
        accessTree_2[4] = new Node(new int[]{2, 2}, new int[][]{{20}, {21}}, 4);
        accessTree_2[5] = new Node(new int[]{2, 2}, new int[][]{{22}, {23}}, 5);
        accessTree_2[6] = new Node(new int[]{2, 2}, new int[][]{{24}, {25}}, 6);
        accessTree_2[7] = new Node(new int[]{3, 3}, new int[][]{{26}, {27}, {28}}, 7);
        accessTree_2[8] = new Node("S", 6, 8);
        accessTree_2[9] = new Node("S", 6, 9);
        accessTree_2[10] = new Node("S", 6, 10);
        accessTree_2[11] = new Node("S", 6, 11);
        accessTree_2[12] = new Node("S", 6, 12);
        accessTree_2[13] = new Node("S", 6, 13);
        accessTree_2[14] = new Node("A", 1, 14);
        accessTree_2[15] = new Node("B", 1, 15);
        accessTree_2[16] = new Node("C", 1, 16);
        accessTree_2[17] = new Node("D", 1, 17);
        accessTree_2[18] = new Node("E", 1, 18);
        accessTree_2[19] = new Node("F", 1, 19);
        accessTree_2[20] = new Node("G", 1, 20);
        accessTree_2[21] = new Node("H", 1, 21);
        accessTree_2[22] = new Node("I", 1, 22);
        accessTree_2[23] = new Node("J", 1, 23);
        accessTree_2[24] = new Node("K", 1, 24);
        accessTree_2[25] = new Node("L", 1, 25);
        accessTree_2[26] = new Node("M", 1, 26);
        accessTree_2[27] = new Node("N", 1, 27);
        accessTree_2[28] = new Node("O", 1, 28);
        int[] level_2 = {1, 2, 3, 4, 5, 6, 7};
        Su[] sus_2 = new Su[7];
        String[] S0_2 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_2 = {{"A", "B"}, {"C", "D"}, {"E", "F"}, {"G", "H"}, {"I", "J"}, {"K", "L"}, {"M", "N", "O"}};

        Node[] accessTree_3 = new Node[40];
        accessTree_3[0] = new Node(new int[]{10,10}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11,12,13,14,15,16,17,18,19}}, 0);
        accessTree_3[1] = new Node(new int[]{2,2}, new int[][]{{20}, {21}}, 1);
        accessTree_3[2] = new Node(new int[]{2,2}, new int[][]{{22}, {23}}, 2);
        accessTree_3[3] = new Node(new int[]{2,2}, new int[][]{{24}, {25}}, 3);
        accessTree_3[4] = new Node(new int[]{2,2}, new int[][]{{26}, {27}}, 4);
        accessTree_3[5] = new Node(new int[]{2,2}, new int[][]{{28}, {29}}, 5);
        accessTree_3[6] = new Node(new int[]{2,2}, new int[][]{{30}, {31}}, 6);
        accessTree_3[7] = new Node(new int[]{2,2}, new int[][]{{32}, {33}}, 7);
        accessTree_3[8] = new Node(new int[]{2,2}, new int[][]{{34}, {35}}, 8);
        accessTree_3[9] = new Node(new int[]{2,2}, new int[][]{{36}, {37}}, 9);
        accessTree_3[10] = new Node(new int[]{2,2}, new int[][]{{38}, {39}}, 10);
        accessTree_3[11] = new Node("S", 9, 11);
        accessTree_3[12] = new Node("S", 9, 12);
        accessTree_3[13] = new Node("S", 9, 13);
        accessTree_3[14] = new Node("S", 9, 14);
        accessTree_3[15] = new Node("S", 9, 15);
        accessTree_3[16] = new Node("S", 9, 16);
        accessTree_3[17] = new Node("S", 9, 17);
        accessTree_3[18] = new Node("S", 9, 18);
        accessTree_3[19] = new Node("S", 9, 19);
        accessTree_3[20] = new Node("A", 1, 20);
        accessTree_3[21] = new Node("B", 1, 21);
        accessTree_3[22] = new Node("C", 1, 22);
        accessTree_3[23] = new Node("D", 1, 23);
        accessTree_3[24] = new Node("E", 1, 24);
        accessTree_3[25] = new Node("F", 1, 25);
        accessTree_3[26] = new Node("G", 1, 26);
        accessTree_3[27] = new Node("H", 1, 27);
        accessTree_3[28] = new Node("I", 1, 28);
        accessTree_3[29] = new Node("J", 1, 29);
        accessTree_3[30] = new Node("K", 1, 30);
        accessTree_3[31] = new Node("L", 1, 31);
        accessTree_3[32] = new Node("M", 1, 32);
        accessTree_3[33] = new Node("N", 1, 33);
        accessTree_3[34] = new Node("O", 1, 34);
        accessTree_3[35] = new Node("P", 1, 35);
        accessTree_3[36] = new Node("Q", 1, 36);
        accessTree_3[37] = new Node("R", 1, 37);
        accessTree_3[38] = new Node("T", 1, 38);
        accessTree_3[39] = new Node("U", 1, 39);
        int[] level_3 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        Su[] sus_3 = new Su[10];
        String[] S0_3 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "T", "U"};
        String[][] S_3 = {{"A", "B"}, {"C", "D"}, {"E", "F"}, {"G", "H"}, {"I", "J"}, {"K", "L"}, {"M", "N"}, {"O", "P"}, {"Q", "R"}, {"T", "U"}};
//
        //--------------------------------------------------------------------------------------------------------------
        //==============================================================================================================
        //--------------------------------------------------------------------------------------------------------------
        //合作节点固定为5，属性数分别为15，20，25，30;
        Node[] accessTree_4 = new Node[25];
        accessTree_4[0] = new Node(new int[]{5, 5}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6, 7, 8, 9}}, 0);
        accessTree_4[1] = new Node(new int[]{3, 3}, new int[][]{{10}, {11}, {12}}, 1);
        accessTree_4[2] = new Node(new int[]{3, 3}, new int[][]{{13}, {14}, {15}}, 2);
        accessTree_4[3] = new Node(new int[]{3, 3}, new int[][]{{16}, {17}, {18}}, 3);
        accessTree_4[4] = new Node(new int[]{3, 3}, new int[][]{{19}, {20}, {21}}, 4);
        accessTree_4[5] = new Node(new int[]{3, 3}, new int[][]{{22}, {23}, {24}}, 5);
        accessTree_4[6] = new Node("S", 4, 6);
        accessTree_4[7] = new Node("S", 4, 7);
        accessTree_4[8] = new Node("S", 4, 8);
        accessTree_4[9] = new Node("S", 4, 9);
        accessTree_4[10] = new Node("A", 1, 10);
        accessTree_4[11] = new Node("B", 1, 11);
        accessTree_4[12] = new Node("C", 1, 12);
        accessTree_4[13] = new Node("D", 1, 13);
        accessTree_4[14] = new Node("E", 1, 14);
        accessTree_4[15] = new Node("F", 1, 15);
        accessTree_4[16] = new Node("G", 1, 16);
        accessTree_4[17] = new Node("H", 1, 17);
        accessTree_4[18] = new Node("I", 1, 18);
        accessTree_4[19] = new Node("J", 1, 19);
        accessTree_4[20] = new Node("K", 1, 20);
        accessTree_4[21] = new Node("L", 1, 21);
        accessTree_4[22] = new Node("M", 1, 22);
        accessTree_4[23] = new Node("N", 1, 23);
        accessTree_4[24] = new Node("O", 1, 24);
        int[] level_4 = {1, 2, 3, 4, 5};
        Su[] sus_4 = new Su[5];
        String[] S0_4 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_4 = {{"A", "B", "C"}, {"D", "E", "F"}, {"G", "H", "I"}, {"J", "K", "L"}, {"M", "N", "O"}};

        Node[] accessTree_5 = new Node[30];
        accessTree_5[0] = new Node(new int[]{5, 5}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6, 7, 8, 9}}, 0);
        accessTree_5[1] = new Node(new int[]{4, 4}, new int[][]{{10}, {11}, {12}, {13}}, 1);
        accessTree_5[2] = new Node(new int[]{4, 4}, new int[][]{{14}, {15}, {16}, {17}}, 2);
        accessTree_5[3] = new Node(new int[]{4, 4}, new int[][]{{18}, {19}, {20}, {21}}, 3);
        accessTree_5[4] = new Node(new int[]{4, 4}, new int[][]{{22}, {23}, {24}, {25}}, 4);
        accessTree_5[5] = new Node(new int[]{4, 4}, new int[][]{{26}, {27}, {28}, {29}}, 5);
        accessTree_5[6] = new Node("S", 4, 6);
        accessTree_5[7] = new Node("S", 4, 7);
        accessTree_5[8] = new Node("S", 4, 8);
        accessTree_5[9] = new Node("S", 4, 9);
        accessTree_5[10] = new Node("A", 1, 10);
        accessTree_5[11] = new Node("B", 1, 11);
        accessTree_5[12] = new Node("C", 1, 12);
        accessTree_5[13] = new Node("D", 1, 13);
        accessTree_5[14] = new Node("E", 1, 14);
        accessTree_5[15] = new Node("F", 1, 15);
        accessTree_5[16] = new Node("G", 1, 16);
        accessTree_5[17] = new Node("H", 1, 17);
        accessTree_5[18] = new Node("I", 1, 18);
        accessTree_5[19] = new Node("J", 1, 19);
        accessTree_5[20] = new Node("K", 1, 20);
        accessTree_5[21] = new Node("L", 1, 21);
        accessTree_5[22] = new Node("M", 1, 22);
        accessTree_5[23] = new Node("N", 1, 23);
        accessTree_5[24] = new Node("O", 1, 24);
        accessTree_5[25] = new Node("P", 1, 25);
        accessTree_5[26] = new Node("Q", 1, 26);
        accessTree_5[27] = new Node("R", 1, 27);
        accessTree_5[28] = new Node("T", 1, 28);
        accessTree_5[29] = new Node("U", 1, 29);
        int[] level_5 = {1, 2, 3, 4, 5};
        Su[] sus_5 = new Su[5];
        String[] S0_5 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "T", "U"};
        String[][] S_5 = {{"A", "B", "C", "D"}, {"E", "F", "G", "H"}, {"I", "J", "K", "L"}, {"M", "N", "O", "P"}, {"Q", "R", "T", "U"}};

        Node[] accessTree_6 = new Node[35];
        accessTree_6[0] = new Node(new int[]{5, 5}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6, 7, 8, 9}}, 0);
        accessTree_6[1] = new Node(new int[]{5, 5}, new int[][]{{10}, {11}, {12}, {13}, {14}}, 1);
        accessTree_6[2] = new Node(new int[]{5, 5}, new int[][]{{15}, {16}, {17}, {18}, {19}}, 2);
        accessTree_6[3] = new Node(new int[]{5, 5}, new int[][]{{20}, {21}, {22}, {23}, {24}}, 3);
        accessTree_6[4] = new Node(new int[]{5, 5}, new int[][]{{25}, {26}, {27}, {28}, {29}}, 4);
        accessTree_6[5] = new Node(new int[]{5, 5}, new int[][]{{30}, {31}, {32}, {33}, {34}}, 5);
        accessTree_6[6] = new Node("S", 4, 6);
        accessTree_6[7] = new Node("S", 4, 7);
        accessTree_6[8] = new Node("S", 4, 8);
        accessTree_6[9] = new Node("S", 4, 9);
        accessTree_6[10] = new Node("A", 1, 10);
        accessTree_6[11] = new Node("B", 1, 11);
        accessTree_6[12] = new Node("C", 1, 12);
        accessTree_6[13] = new Node("D", 1, 13);
        accessTree_6[14] = new Node("E", 1, 14);
        accessTree_6[15] = new Node("F", 1, 15);
        accessTree_6[16] = new Node("G", 1, 16);
        accessTree_6[17] = new Node("H", 1, 17);
        accessTree_6[18] = new Node("I", 1, 18);
        accessTree_6[19] = new Node("J", 1, 19);
        accessTree_6[20] = new Node("K", 1, 20);
        accessTree_6[21] = new Node("L", 1, 21);
        accessTree_6[22] = new Node("M", 1, 22);
        accessTree_6[23] = new Node("N", 1, 23);
        accessTree_6[24] = new Node("O", 1, 24);
        accessTree_6[25] = new Node("P", 1, 25);
        accessTree_6[26] = new Node("Q", 1, 26);
        accessTree_6[27] = new Node("R", 1, 27);
        accessTree_6[28] = new Node("T", 1, 28);
        accessTree_6[29] = new Node("U", 1, 29);
        accessTree_6[30] = new Node("V", 1, 30);
        accessTree_6[31] = new Node("W", 1, 31);
        accessTree_6[32] = new Node("X", 1, 32);
        accessTree_6[33] = new Node("Y", 1, 33);
        accessTree_6[34] = new Node("Z", 1, 34);
        int[] level_6 = {1, 2, 3, 4, 5};
        Su[] sus_6 = new Su[5];
        String[] S0_6 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "T",
                "U", "V", "W", "X", "Y", "Z"};
        String[][] S_6 = {{"A", "B", "C", "D", "E"}, {"F", "G", "H", "I", "J"}, {"K", "L", "M", "N", "O"},
                {"P", "Q", "R", "T", "U"}, {"V", "W", "X", "Y", "Z"}};

        Node[] accessTree_7 = new Node[40];
        accessTree_7[0] = new Node(new int[]{5, 5}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6, 7, 8, 9}}, 0);
        accessTree_7[1] = new Node(new int[]{6, 6}, new int[][]{{10}, {11}, {12}, {13}, {14}, {15}}, 1);
        accessTree_7[2] = new Node(new int[]{6, 6}, new int[][]{{16}, {17}, {18}, {19}, {20}, {21}}, 2);
        accessTree_7[3] = new Node(new int[]{6, 6}, new int[][]{{22}, {23}, {24}, {25}, {26}, {27}}, 3);
        accessTree_7[4] = new Node(new int[]{6, 6}, new int[][]{{28}, {29}, {30}, {31}, {32}, {33}}, 4);
        accessTree_7[5] = new Node(new int[]{6, 6}, new int[][]{{34}, {35}, {36}, {37}, {38}, {39}}, 5);
        accessTree_7[6] = new Node("S", 4, 6);
        accessTree_7[7] = new Node("S", 4, 7);
        accessTree_7[8] = new Node("S", 4, 8);
        accessTree_7[9] = new Node("S", 4, 9);
        accessTree_7[10] = new Node("A", 1, 10);
        accessTree_7[11] = new Node("B", 1, 11);
        accessTree_7[12] = new Node("C", 1, 12);
        accessTree_7[13] = new Node("D", 1, 13);
        accessTree_7[14] = new Node("E", 1, 14);
        accessTree_7[15] = new Node("F", 1, 15);
        accessTree_7[16] = new Node("G", 1, 16);
        accessTree_7[17] = new Node("H", 1, 17);
        accessTree_7[18] = new Node("I", 1, 18);
        accessTree_7[19] = new Node("J", 1, 19);
        accessTree_7[20] = new Node("K", 1, 20);
        accessTree_7[21] = new Node("L", 1, 21);
        accessTree_7[22] = new Node("M", 1, 22);
        accessTree_7[23] = new Node("N", 1, 23);
        accessTree_7[24] = new Node("O", 1, 24);
        accessTree_7[25] = new Node("P", 1, 25);
        accessTree_7[26] = new Node("Q", 1, 26);
        accessTree_7[27] = new Node("R", 1, 27);
        accessTree_7[28] = new Node("T", 1, 28);
        accessTree_7[29] = new Node("U", 1, 29);
        accessTree_7[30] = new Node("V", 1, 30);
        accessTree_7[31] = new Node("W", 1, 31);
        accessTree_7[32] = new Node("X", 1, 32);
        accessTree_7[33] = new Node("Y", 1, 33);
        accessTree_7[34] = new Node("Z", 1, 34);
        accessTree_7[35] = new Node("A1", 1, 35);
        accessTree_7[36] = new Node("A2", 1, 36);
        accessTree_7[37] = new Node("A3", 1, 37);
        accessTree_7[38] = new Node("A4", 1, 38);
        accessTree_7[39] = new Node("A5", 1, 39);
        int[] level_7 = {1, 2, 3, 4, 5};
        Su[] sus_7 = new Su[5];
        String[] S0_7 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "T",
                "U", "V", "W", "X", "Y", "Z", "A1", "A2", "A3", "A4", "A5"};
        String[][] S_7 = {{"A", "B", "C", "D", "E", "F"}, {"G", "H", "I", "J", "K", "L"}, {"M", "N", "O", "P", "Q", "R"},
                {"T", "U", "V", "W", "X", "Y"}, {"Z", "A1", "A2", "A3", "A4", "A5"}};


        Node[] accessTree_xx = new Node[33];
        accessTree_xx[0] = new Node(new int[]{9,9}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10,11,12,13,14,15,16,17}}, 0);
        accessTree_xx[1] = new Node(new int[]{2,2}, new int[][]{{18}, {19}}, 1);
        accessTree_xx[2] = new Node(new int[]{2,2}, new int[][]{{20}, {21}}, 2);
        accessTree_xx[3] = new Node(new int[]{2,2}, new int[][]{{22}, {23}}, 3);
        accessTree_xx[4] = new Node(new int[]{2,2}, new int[][]{{24}, {25}}, 4);
        accessTree_xx[5] = new Node(new int[]{2,2}, new int[][]{{26}, {27}}, 5);
        accessTree_xx[6] = new Node(new int[]{1,1}, new int[][]{{28}}, 6);
        accessTree_xx[7] = new Node(new int[]{1,1}, new int[][]{{29}}, 7);
        accessTree_xx[8] = new Node(new int[]{1,1}, new int[][]{{30}}, 8);
        accessTree_xx[9] = new Node(new int[]{2,2}, new int[][]{{31}, {32}}, 9);
        accessTree_xx[10] = new Node("S", 8, 10);
        accessTree_xx[11] = new Node("S", 8, 11);
        accessTree_xx[12] = new Node("S", 8, 12);
        accessTree_xx[13] = new Node("S", 8, 13);
        accessTree_xx[14] = new Node("S", 8, 14);
        accessTree_xx[15] = new Node("S", 8, 15);
        accessTree_xx[16] = new Node("S", 8, 16);
        accessTree_xx[17] = new Node("S", 8, 17);
        accessTree_xx[18] = new Node("A", 1, 18);
        accessTree_xx[19] = new Node("B", 1, 19);
        accessTree_xx[20] = new Node("C", 1, 20);
        accessTree_xx[21] = new Node("D", 1, 21);
        accessTree_xx[22] = new Node("E", 1, 22);
        accessTree_xx[23] = new Node("F", 1, 23);
        accessTree_xx[24] = new Node("G", 1, 24);
        accessTree_xx[25] = new Node("H", 1, 25);
        accessTree_xx[26] = new Node("I", 1, 26);
        accessTree_xx[27] = new Node("J", 1, 27);
        accessTree_xx[28] = new Node("K", 1, 28);
        accessTree_xx[29] = new Node("L", 1, 29);
        accessTree_xx[30] = new Node("M", 1, 30);
        accessTree_xx[31] = new Node("N", 1, 31);
        accessTree_xx[32] = new Node("O", 1, 32);
        int[] level_xx = {1, 2, 3, 4, 5, 6, 7, 8, 9};
        Su[] sus_xx = new Su[9];
        String[] S0_xx = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_xx = {{"A", "B"}, {"C", "D"}, {"E", "F"}, {"G", "H"}, {"I", "J"}, {"K"}, {"L"}, {"M"}, {"N", "O"}};

        Node[] accessTree_3_x = new Node[9];
        accessTree_3_x[0] = new Node(new int[]{3, 3}, new int[][]{{1}, {2}, {3}, {4, 5}}, 0);
        accessTree_3_x[1] = new Node(new int[]{1, 1}, new int[][]{{6}}, 1);
        accessTree_3_x[2] = new Node(new int[]{1, 1}, new int[][]{{7}}, 2);
        accessTree_3_x[3] = new Node(new int[]{1, 1}, new int[][]{{8}}, 3);
        accessTree_3_x[4] = new Node("S", 2, 4);
        accessTree_3_x[5] = new Node("S", 2, 5);
        accessTree_3_x[6] = new Node("A", 1, 6);
        accessTree_3_x[7] = new Node("B", 1, 7);
        accessTree_3_x[8] = new Node("C", 1, 8);
        int[] level_3_x = {1,2,3};
        Su[] sus_3_x = new Su[3];
        String[] S0_3_x = {"A", "B", "C"};
        String[][] S_3_x = {{"A"}, {"B"}, {"C"}};

        Node[] accessTree_5_x = new Node[15];
        accessTree_5_x[0] = new Node(new int[]{5, 5}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6, 7, 8, 9}}, 0);
        accessTree_5_x[1] = new Node(new int[]{1, 1}, new int[][]{{10}}, 1);
        accessTree_5_x[2] = new Node(new int[]{1, 1}, new int[][]{{11}}, 2);
        accessTree_5_x[3] = new Node(new int[]{1, 1}, new int[][]{{12}}, 3);
        accessTree_5_x[4] = new Node(new int[]{1, 1}, new int[][]{{13}}, 4);
        accessTree_5_x[5] = new Node(new int[]{1, 1}, new int[][]{{14}}, 5);
        accessTree_5_x[6] = new Node("S", 4, 6);
        accessTree_5_x[7] = new Node("S", 4, 7);
        accessTree_5_x[8] = new Node("S", 4, 8);
        accessTree_5_x[9] = new Node("S", 4, 9);
        accessTree_5_x[10] = new Node("A", 1, 10);
        accessTree_5_x[11] = new Node("B", 1, 11);
        accessTree_5_x[12] = new Node("C", 1, 12);
        accessTree_5_x[13] = new Node("D", 1, 13);
        accessTree_5_x[14] = new Node("E", 1, 14);
        int[] level_5_x = {1, 2, 3, 4, 5};
        Su[] sus_5_x = new Su[5];
        String[] S0_5_x = {"A", "B", "C", "D", "E"};
        String[][] S_5_x = {{"A"}, {"B"}, {"C"}, {"D"}, {"E"}};

        Node[] accessTree_7_x = new Node[21];
        accessTree_7_x[0] = new Node(new int[]{7, 7}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8,9,10,11,12,13}}, 0);
        accessTree_7_x[1] = new Node(new int[]{1, 1}, new int[][]{{14}}, 1);
        accessTree_7_x[2] = new Node(new int[]{1, 1}, new int[][]{{15}}, 2);
        accessTree_7_x[3] = new Node(new int[]{1, 1}, new int[][]{{16}}, 3);
        accessTree_7_x[4] = new Node(new int[]{1, 1}, new int[][]{{17}}, 4);
        accessTree_7_x[5] = new Node(new int[]{1, 1}, new int[][]{{18}}, 5);
        accessTree_7_x[6] = new Node(new int[]{1, 1}, new int[][]{{19}}, 6);
        accessTree_7_x[7] = new Node(new int[]{1, 1}, new int[][]{{20}}, 7);
        accessTree_7_x[8] = new Node("S", 6, 8);
        accessTree_7_x[9] = new Node("S", 6, 9);
        accessTree_7_x[10] = new Node("S", 6, 10);
        accessTree_7_x[11] = new Node("S", 6, 11);
        accessTree_7_x[12] = new Node("S", 6, 12);
        accessTree_7_x[13] = new Node("S", 6, 13);
        accessTree_7_x[14] = new Node("A", 1, 14);
        accessTree_7_x[15] = new Node("B", 1, 15);
        accessTree_7_x[16] = new Node("C", 1, 16);
        accessTree_7_x[17] = new Node("D", 1, 17);
        accessTree_7_x[18] = new Node("E", 1, 18);
        accessTree_7_x[19] = new Node("F", 1, 19);
        accessTree_7_x[20] = new Node("G", 1, 20);
        int[] level_7_x = {1, 2, 3, 4, 5, 6, 7};
        Su[] sus_7_x = new Su[7];
        String[] S0_7_x = {"A", "B", "C", "D", "E", "F", "G"};
        String[][] S_7_x = {{"A"}, {"B"}, {"C"}, {"D"}, {"E"}, {"F"}, {"G"}};

        Node[] accessTree_9_x = new Node[27];
        accessTree_9_x[0] = new Node(new int[]{9,9}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10,11,12,13,14,15,16,17}}, 0);
        accessTree_9_x[1] = new Node(new int[]{1,1}, new int[][]{{18}}, 1);
        accessTree_9_x[2] = new Node(new int[]{1,1}, new int[][]{{19}}, 2);
        accessTree_9_x[3] = new Node(new int[]{1,1}, new int[][]{{20}}, 3);
        accessTree_9_x[4] = new Node(new int[]{1,1}, new int[][]{{21}}, 4);
        accessTree_9_x[5] = new Node(new int[]{1,1}, new int[][]{{22}}, 5);
        accessTree_9_x[6] = new Node(new int[]{1,1}, new int[][]{{23}}, 6);
        accessTree_9_x[7] = new Node(new int[]{1,1}, new int[][]{{24}}, 7);
        accessTree_9_x[8] = new Node(new int[]{1,1}, new int[][]{{25}}, 8);
        accessTree_9_x[9] = new Node(new int[]{1,1}, new int[][]{{26}}, 9);
        accessTree_9_x[10] = new Node("S", 8, 10);
        accessTree_9_x[11] = new Node("S", 8, 11);
        accessTree_9_x[12] = new Node("S", 8, 12);
        accessTree_9_x[13] = new Node("S", 8, 13);
        accessTree_9_x[14] = new Node("S", 8, 14);
        accessTree_9_x[15] = new Node("S", 8, 15);
        accessTree_9_x[16] = new Node("S", 8, 16);
        accessTree_9_x[17] = new Node("S", 8, 17);
        accessTree_9_x[18] = new Node("A", 1, 18);
        accessTree_9_x[19] = new Node("B", 1, 19);
        accessTree_9_x[20] = new Node("C", 1, 20);
        accessTree_9_x[21] = new Node("D", 1, 21);
        accessTree_9_x[22] = new Node("E", 1, 22);
        accessTree_9_x[23] = new Node("F", 1, 23);
        accessTree_9_x[24] = new Node("G", 1, 24);
        accessTree_9_x[25] = new Node("H", 1, 25);
        accessTree_9_x[26] = new Node("I", 1, 26);
        int[] level_9_x = {1, 2, 3, 4, 5, 6, 7, 8, 9};
        Su[] sus_9_x = new Su[9];
        String[] S0_9_x = {"A", "B", "C", "D", "E", "F", "G", "H", "I"};
        String[][] S_9_x = {{"A"}, {"B"}, {"C"}, {"D"}, {"E"}, {"F"}, {"G"}, {"H"}, {"I"}};

        //--------------------------------------------------------------------------------------------------------------
        //==============================================================================================================
        //--------------------------------------------------------------------------------------------------------------
        Node[][] accessTree_n = {accessTree_0, accessTree_1, accessTree_2, accessTree_3, accessTree_4, accessTree_5,
                accessTree_6, accessTree_7, accessTree_xx, accessTree_3_x, accessTree_5_x, accessTree_7_x, accessTree_9_x};
        int[][] level_n = {level_0, level_1, level_2, level_3, level_4, level_5, level_6, level_7, level_xx, level_3_x,
                level_5_x, level_7_x, level_9_x};
        Su[][] sus_n = {sus_0, sus_1, sus_2, sus_3, sus_4, sus_5, sus_6, sus_7, sus_xx, sus_3_x, sus_5_x, sus_7_x, sus_9_x};
        String[][] S0_n = {S0_0, S0_1, S0_2, S0_3, S0_4, S0_5, S0_6, S0_7, S0_xx, S0_3_x, S0_5_x, S0_7_x, S0_9_x};
        String[][][] S_n = {S_0, S_1, S_2, S_3, S_4, S_5, S_6, S_7, S_xx, S_3_x, S_5_x, S_7_x, S_9_x};
        //0-3 合作节点分别为3，5，7，10，每个合作节点固定两个子节点。
        //4-7 合作节点固定为5，每个节点子节点为3，4，5，6。
        //8 添加9
        // 9-10-11-12
        int tree = 12; //选择树
        Node[] accessTree = accessTree_n[tree];
        int[] level = level_n[tree];
        Su[] sus = sus_n[tree];
        String[] S0 = S0_n[tree];
        String[][] S = S_n[tree];

        //--------------------------------------------------------------------------------------------------------------
        //==============================================================================================================
        //--------------------------------------------------------------------------------------------------------------


        //1-14
        //int n=1;

        String message = "wanghao1";
        Element decrypt_message = null;
        Element share_decrypt_message = null;
        Element test_message = bp.getGT().newElementFromBytes(message.getBytes()).getImmutable();

//        Node[] accessTree = null;
//        int[] level = null;
//        Su[] sus = null;
//        String[] S0 = null;
//        String[][] S = null;
//        long[] result_en = new long[14];
//        //初始化
//        Setup(pairingPropertiesFileName, mskFileName, pkFileName);
//
//        for(int number = 14; number<28; number++) {
//
//            Node[] accessTree_0 = null;
//            int[] level_0 = null;
//            Su[] sus_0 = null;
//            String[] S0_0 = null;
//            String[][] S_0 = null;
//
//            Node[] accessTree_1 = new Node[number + 2];
//            accessTree_1[0] = new Node(new int[]{1, 1}, new int[][]{{1}}, 0);
//            int[][] last_node_1 = new int[number][1];
//            String[] last_att_1 = new String[number];
//            for (int i = 2; i < accessTree_1.length; i++) {
//                last_node_1[i - 2][0] = i;
//                last_att_1[i - 2] = "A" + i;
//            }
//            accessTree_1[1] = new Node(new int[]{14, 14}, last_node_1, 1);
//            for (int i = 2; i < accessTree_1.length; i++) {
//                String att = "A" + i;
//                accessTree_1[i] = new Node(att, 1, i);
//            }
//            int[] level_1 = {1};
//            Su[] sus_1 = new Su[1];
//            String[] S0_1 = new String[number];
//            for (int i = 2; i < accessTree_1.length; i++) {
//                String att = "A" + i;
//                S0_1[i - 2] = att;
//            }
//            String[][] S_1 = {last_att_1};
//
//            Node[] accessTree_2 = new Node[number + 4];
//            accessTree_2[0] = new Node(new int[]{2, 2}, new int[][]{{1}, {2}, {3}}, 0);
//            accessTree_2[1] = new Node(new int[]{7, 7}, new int[][]{{4}, {5}, {6}, {7}, {8}, {9}, {10}}, 1);
//            int[][] last_node_2 = new int[number - 7][1];
//            String[] last_att_2 = new String[number - 7];
//            for (int i = 11; i < accessTree_2.length; i++) {
//                last_node_2[i - 11][0] = i;
//                last_att_2[i - 11] = "A" + i;
//            }
//            accessTree_2[2] = new Node(new int[]{7, 7}, last_node_2, 2);
//            for (int i = 3; i < 4; i++) {
//                String att = "S";
//                accessTree_2[i] = new Node(att, 1, i);
//            }
//            for (int i = 4; i < accessTree_2.length; i++) {
//                String att = "A" + i;
//                accessTree_2[i] = new Node(att, 1, i);
//            }
//            int[] level_2 = {1, 2};
//            Su[] sus_2 = new Su[2];
//            String[] S0_2 = new String[number];
//            for (int i = 4; i < accessTree_2.length; i++) {
//                String att = "A" + i;
//                S0_2[i - 4] = att;
//            }
//            String[][] S_2 = {{"A4", "A5", "A6", "A7", "A8", "A9", "A10"}, last_att_2};
//
//            Node[] accessTree_3 = new Node[number + 6];
//            accessTree_3[0] = new Node(new int[]{3, 3}, new int[][]{{1}, {2}, {3}, {4, 5}}, 0);
//            accessTree_3[1] = new Node(new int[]{4, 4}, new int[][]{{6}, {7}, {8}, {9}}, 1);
//            accessTree_3[2] = new Node(new int[]{4, 4}, new int[][]{{10}, {11}, {12}, {13}}, 2);
//            int[][] last_node_3 = new int[number - 8][1];
//            String[] last_att_3 = new String[number - 8];
//            for (int i = 14; i < accessTree_3.length; i++) {
//                last_node_3[i - 14][0] = i;
//                last_att_3[i - 14] = "A" + i;
//            }
//            accessTree_3[3] = new Node(new int[]{6, 6}, last_node_3, 3);
//            for (int i = 4; i < 6; i++) {
//                String att = "S";
//                accessTree_3[i] = new Node(att, 2, i);
//            }
//            for (int i = 6; i < accessTree_3.length; i++) {
//                String att = "A" + i;
//                accessTree_3[i] = new Node(att, 1, i);
//            }
//            int[] level_3 = {1, 2, 3};
//            Su[] sus_3 = new Su[3];
//            String[] S0_3 = new String[number];
//            for (int i = 6; i < accessTree_3.length; i++) {
//                String att = "A" + i;
//                S0_3[i - 6] = att;
//            }
//            String[][] S_3 = {{"A6", "A7", "A8", "A9"}, {"A10", "A11", "A12", "A13"}, last_att_3};
//
//            Node[] accessTree_4 = new Node[number + 8];
//            accessTree_4[0] = new Node(new int[]{4, 4}, new int[][]{{1}, {2}, {3}, {4}, {5, 6, 7}}, 0);
//            accessTree_4[1] = new Node(new int[]{3, 3}, new int[][]{{8}, {9}, {10}}, 1);
//            accessTree_4[2] = new Node(new int[]{3, 3}, new int[][]{{11}, {12}, {13}}, 2);
//            accessTree_4[3] = new Node(new int[]{4, 4}, new int[][]{{14}, {15}, {16}, {17}}, 3);
//            int[][] last_node_4 = new int[number - 10][1];
//            String[] last_att_4 = new String[number - 10];
//            for (int i = 18; i < accessTree_4.length; i++) {
//                last_node_4[i - 18][0] = i;
//                last_att_4[i - 18] = "A" + i;
//            }
//            accessTree_4[4] = new Node(new int[]{4, 4}, last_node_4, 4);
//            for (int i = 5; i < 8; i++) {
//                String att = "S";
//                accessTree_4[i] = new Node(att, 3, i);
//            }
//            for (int i = 8; i < accessTree_4.length; i++) {
//                String att = "A" + i;
//                accessTree_4[i] = new Node(att, 1, i);
//            }
//            int[] level_4 = {1, 2, 3, 4};
//            Su[] sus_4 = new Su[4];
//            String[] S0_4 = new String[number];
//            for (int i = 8; i < accessTree_4.length; i++) {
//                String att = "A" + i;
//                S0_4[i - 8] = att;
//            }
//            String[][] S_4 = {{"A8", "A9", "A10"}, {"A11", "A12", "A13"}, {"A14", "A15", "A16", "A17"}, last_att_4};
//
//            Node[] accessTree_5 = new Node[number + 10];
//            accessTree_5[0] = new Node(new int[]{5, 5}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6, 7, 8, 9}}, 0);
//            accessTree_5[1] = new Node(new int[]{3, 3}, new int[][]{{10}, {11}, {12}}, 1);
//            accessTree_5[2] = new Node(new int[]{3, 3}, new int[][]{{13}, {14}, {15}}, 2);
//            accessTree_5[3] = new Node(new int[]{3, 3}, new int[][]{{16}, {17}, {18}}, 3);
//            accessTree_5[4] = new Node(new int[]{2, 2}, new int[][]{{19}, {20}}, 4);
//            int[][] last_node_5 = new int[number - 11][1];
//            String[] last_att_5 = new String[number - 11];
//            for (int i = 21; i < accessTree_5.length; i++) {
//                last_node_5[i - 21][0] = i;
//                last_att_5[i - 21] = "A" + i;
//            }
//            accessTree_5[5] = new Node(new int[]{3, 3}, last_node_5, 5);
//            for (int i = 6; i < 10; i++) {
//                String att = "S";
//                accessTree_5[i] = new Node(att, 4, i);
//            }
//            for (int i = 10; i < accessTree_5.length; i++) {
//                String att = "A" + i;
//                accessTree_5[i] = new Node(att, 1, i);
//            }
//            int[] level_5 = {1, 2, 3, 4, 5};
//            Su[] sus_5 = new Su[5];
//            String[] S0_5 = new String[number];
//            for (int i = 10; i < accessTree_5.length; i++) {
//                String att = "A" + i;
//                S0_5[i - 10] = att;
//            }
//            String[][] S_5 = {{"A10", "A11", "A12"}, {"A13", "A14", "A15"}, {"A16", "A17", "A18"}, {"A19", "A20"}, last_att_5};
//
//            Node[] accessTree_6 = new Node[number + 12];
//            accessTree_6[0] = new Node(new int[]{6, 6}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7, 8, 9, 10, 11}}, 0);
//            accessTree_6[1] = new Node(new int[]{3, 3}, new int[][]{{12}, {13}, {14}}, 1);
//            accessTree_6[2] = new Node(new int[]{3, 3}, new int[][]{{15}, {16}, {17}}, 2);
//            accessTree_6[3] = new Node(new int[]{2, 2}, new int[][]{{18}, {19}}, 3);
//            accessTree_6[4] = new Node(new int[]{2, 2}, new int[][]{{20}, {21}}, 4);
//            accessTree_6[5] = new Node(new int[]{2, 2}, new int[][]{{22}, {23}}, 5);
//            int[][] last_node_6 = new int[number - 12][1];
//            String[] last_att_6 = new String[number - 12];
//            for (int i = 24; i < accessTree_6.length; i++) {
//                last_node_6[i - 24][0] = i;
//                last_att_6[i - 24] = "A" + i;
//            }
//            accessTree_6[6] = new Node(new int[]{2, 2}, last_node_6, 6);
//            for (int i = 7; i < 12; i++) {
//                String att = "S";
//                accessTree_6[i] = new Node(att, 5, i);
//            }
//            for (int i = 12; i < accessTree_6.length; i++) {
//                String att = "A" + i;
//                accessTree_6[i] = new Node(att, 1, i);
//            }
//            int[] level_6 = {1, 2, 3, 4, 5, 6};
//            Su[] sus_6 = new Su[6];
//            String[] S0_6 = new String[number];
//            for (int i = 12; i < accessTree_6.length; i++) {
//                String att = "A" + i;
//                S0_6[i - 12] = att;
//            }
//            String[][] S_6 = {{"A12", "A13", "A14"}, {"A15", "A16", "A17"}, {"A18", "A19"}, {"A20", "A21"},
//                    {"A22", "A23"}, last_att_6};
//
//            Node[] accessTree_7 = new Node[number + 14];
//            accessTree_7[0] = new Node(new int[]{7, 7}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8, 9, 10, 11, 12, 13}}, 0);
//            accessTree_7[1] = new Node(new int[]{2, 2}, new int[][]{{14}, {15}}, 1);
//            accessTree_7[2] = new Node(new int[]{2, 2}, new int[][]{{16}, {17}}, 2);
//            accessTree_7[3] = new Node(new int[]{2, 2}, new int[][]{{18}, {19}}, 3);
//            accessTree_7[4] = new Node(new int[]{2, 2}, new int[][]{{20}, {21}}, 4);
//            accessTree_7[5] = new Node(new int[]{2, 2}, new int[][]{{22}, {23}}, 5);
//            accessTree_7[6] = new Node(new int[]{2, 2}, new int[][]{{24}, {25}}, 6);
//            int[][] last_node_7 = new int[number - 12][1];
//            String[] last_att_7 = new String[number - 12];
//            for (int i = 26; i < accessTree_7.length; i++) {
//                last_node_7[i - 26][0] = i;
//                last_att_7[i - 26] = "A" + i;
//            }
//            accessTree_7[7] = new Node(new int[]{2, 2}, last_node_7, 7);
//            for (int i = 8; i < 14; i++) {
//                String att = "S";
//                accessTree_7[i] = new Node(att, 6, i);
//            }
//            for (int i = 14; i < accessTree_7.length; i++) {
//                String att = "A" + i;
//                accessTree_7[i] = new Node(att, 1, i);
//            }
//            int[] level_7 = {1, 2, 3, 4, 5, 6, 7};
//            Su[] sus_7 = new Su[7];
//            String[] S0_7 = new String[number];
//            for (int i = 14; i < accessTree_7.length; i++) {
//                String att = "A" + i;
//                S0_7[i - 14] = att;
//            }
//            String[][] S_7 = {{"A14", "A15"}, {"A16", "A17"}, {"A18", "A19"}, {"A20", "A21"}, {"A22", "A23"},
//                    {"A24", "A25"}, last_att_7};
//
//            Node[] accessTree_8 = new Node[number + 16];
//            accessTree_8[0] = new Node(new int[]{8, 8}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9, 10, 11, 12, 13, 14, 15}}, 0);
//            accessTree_8[1] = new Node(new int[]{1, 1}, new int[][]{{16}}, 1);
//            accessTree_8[2] = new Node(new int[]{1, 1}, new int[][]{{17}}, 2);
//            accessTree_8[3] = new Node(new int[]{2, 2}, new int[][]{{18}, {19}}, 3);
//            accessTree_8[4] = new Node(new int[]{2, 2}, new int[][]{{20}, {21}}, 4);
//            accessTree_8[5] = new Node(new int[]{2, 2}, new int[][]{{22}, {23}}, 5);
//            accessTree_8[6] = new Node(new int[]{2, 2}, new int[][]{{24}, {25}}, 6);
//            accessTree_8[7] = new Node(new int[]{2, 2}, new int[][]{{26}, {27}}, 7);
//            int[][] last_node_8 = new int[number - 12][1];
//            String[] last_att_8 = new String[number - 12];
//            for (int i = 28; i < accessTree_8.length; i++) {
//                last_node_8[i - 28][0] = i;
//                last_att_8[i - 28] = "A" + i;
//            }
//            accessTree_8[8] = new Node(new int[]{2, 2}, last_node_8, 8);
//            for (int i = 9; i < 16; i++) {
//                String att = "S";
//                accessTree_8[i] = new Node(att, 7, i);
//            }
//            for (int i = 16; i < accessTree_8.length; i++) {
//                String att = "A" + i;
//                accessTree_8[i] = new Node(att, 1, i);
//            }
//            int[] level_8 = {1, 2, 3, 4, 5, 6, 7, 8};
//            Su[] sus_8 = new Su[8];
//            String[] S0_8 = new String[number];
//            for (int i = 16; i < accessTree_8.length; i++) {
//                String att = "A" + i;
//                S0_8[i - 16] = att;
//            }
//            String[][] S_8 = {{"A16"}, {"A17"}, {"A18", "A19"}, {"A20", "A21"}, {"A22", "A23"}, {"A24", "A25"},
//                    {"A26", "A27"}, last_att_8};
//
//            Node[] accessTree_9 = new Node[number + 18];
//            accessTree_9[0] = new Node(new int[]{8, 8}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10, 11, 12, 13, 14, 15, 16, 17}}, 0);
//            accessTree_9[1] = new Node(new int[]{1, 1}, new int[][]{{18}}, 1);
//            accessTree_9[2] = new Node(new int[]{1, 1}, new int[][]{{19}}, 2);
//            accessTree_9[3] = new Node(new int[]{2, 2}, new int[][]{{20}, {21}}, 3);
//            accessTree_9[4] = new Node(new int[]{2, 2}, new int[][]{{22}, {23}}, 4);
//            accessTree_9[5] = new Node(new int[]{2, 2}, new int[][]{{24}, {25}}, 5);
//            accessTree_9[6] = new Node(new int[]{2, 2}, new int[][]{{26}, {27}}, 6);
//            accessTree_9[7] = new Node(new int[]{2, 2}, new int[][]{{28}, {29}}, 7);
//            accessTree_9[8] = new Node(new int[]{1, 1}, new int[][]{{30}}, 8);
//            int[][] last_node_9 = new int[number - 13][1];
//            String[] last_att_9 = new String[number - 13];
//            for (int i = 31; i < accessTree_9.length; i++) {
//                last_node_9[i - 31][0] = i;
//                last_att_9[i - 31] = "A" + i;
//            }
//            accessTree_9[9] = new Node(new int[]{1, 1}, last_node_9, 9);
//            for (int i = 10; i < 18; i++) {
//                String att = "S";
//                accessTree_9[i] = new Node(att, 8, i);
//            }
//            for (int i = 18; i < accessTree_9.length; i++) {
//                String att = "A" + i;
//                accessTree_9[i] = new Node(att, 1, i);
//            }
//            int[] level_9 = {1, 2, 3, 4, 5, 6, 7, 8, 9};
//            Su[] sus_9 = new Su[9];
//            String[] S0_9 = new String[number];
//            for (int i = 18; i < accessTree_9.length; i++) {
//                String att = "A" + i;
//                S0_9[i - 18] = att;
//            }
//            String[][] S_9 = {{"A18"}, {"A19"}, {"A20", "A21"}, {"A22", "A23"}, {"A24", "A25"}, {"A26", "A27"},
//                    {"A28", "A29"}, {"A30"}, last_att_9};
//
//            Node[] accessTree_10 = new Node[number + 20];
//            accessTree_10[0] = new Node(new int[]{8, 8}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10},
//                    {11, 12, 13, 14, 15, 16, 17, 18, 19}}, 0);
//            accessTree_10[1] = new Node(new int[]{1, 1}, new int[][]{{20}}, 1);
//            accessTree_10[2] = new Node(new int[]{1, 1}, new int[][]{{21}}, 2);
//            accessTree_10[3] = new Node(new int[]{1, 1}, new int[][]{{22}}, 3);
//            accessTree_10[4] = new Node(new int[]{1, 1}, new int[][]{{23}}, 4);
//            accessTree_10[5] = new Node(new int[]{1, 1}, new int[][]{{24}}, 5);
//            accessTree_10[6] = new Node(new int[]{2, 2}, new int[][]{{25}, {26}}, 6);
//            accessTree_10[7] = new Node(new int[]{2, 2}, new int[][]{{27}, {28}}, 7);
//            accessTree_10[8] = new Node(new int[]{2, 2}, new int[][]{{29}, {30}}, 8);
//            accessTree_10[9] = new Node(new int[]{2, 2}, new int[][]{{31}, {32}}, 9);
//            int[][] last_node_10 = new int[number - 13][1];
//            String[] last_att_10 = new String[number - 13];
//            for (int i = 33; i < accessTree_10.length; i++) {
//                last_node_10[i - 33][0] = i;
//                last_att_10[i - 33] = "A" + i;
//            }
//            accessTree_10[10] = new Node(new int[]{1, 1}, last_node_10, 10);
//            for (int i = 11; i < 20; i++) {
//                String att = "S";
//                accessTree_10[i] = new Node(att, 9, i);
//            }
//            for (int i = 20; i < accessTree_10.length; i++) {
//                String att = "A" + i;
//                accessTree_10[i] = new Node(att, 1, i);
//            }
//            int[] level_10 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
//            Su[] sus_10 = new Su[10];
//            String[] S0_10 = new String[number];
//            for (int i = 20; i < accessTree_10.length; i++) {
//                String att = "A" + i;
//                S0_10[i - 20] = att;
//            }
//            String[][] S_10 = {{"A20"}, {"A21"}, {"A22"}, {"A23"}, {"A24"}, {"A25", "A26"}, {"A27", "A28"}, {"A29", "A30"},
//                    {"A31", "A32"}, last_att_10};
//
//            Node[] accessTree_11 = new Node[number + 22];
//            accessTree_11[0] = new Node(new int[]{8, 8}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11},
//                    {12, 13, 14, 15, 16, 17, 18, 19, 20, 21}}, 0);
//            accessTree_11[1] = new Node(new int[]{1, 1}, new int[][]{{22}}, 1);
//            accessTree_11[2] = new Node(new int[]{1, 1}, new int[][]{{23}}, 2);
//            accessTree_11[3] = new Node(new int[]{1, 1}, new int[][]{{24}}, 3);
//            accessTree_11[4] = new Node(new int[]{1, 1}, new int[][]{{25}}, 4);
//            accessTree_11[5] = new Node(new int[]{1, 1}, new int[][]{{26}}, 5);
//            accessTree_11[6] = new Node(new int[]{2, 2}, new int[][]{{27}, {28}}, 6);
//            accessTree_11[7] = new Node(new int[]{2, 2}, new int[][]{{29}, {30}}, 7);
//            accessTree_11[8] = new Node(new int[]{2, 2}, new int[][]{{31}, {32}}, 8);
//            accessTree_11[9] = new Node(new int[]{1, 1}, new int[][]{{33}}, 9);
//            accessTree_11[10] = new Node(new int[]{1, 1}, new int[][]{{34}}, 10);
//            int[][] last_node_11 = new int[number - 13][1];
//            String[] last_att_11 = new String[number - 13];
//            for (int i = 35; i < accessTree_11.length; i++) {
//                last_node_11[i - 35][0] = i;
//                last_att_11[i - 35] = "A" + i;
//            }
//            accessTree_11[11] = new Node(new int[]{1, 1}, last_node_11, 11);
//            for (int i = 12; i < 22; i++) {
//                String att = "S";
//                accessTree_11[i] = new Node(att, 10, i);
//            }
//            for (int i = 22; i < accessTree_11.length; i++) {
//                String att = "A" + i;
//                accessTree_11[i] = new Node(att, 1, i);
//            }
//            int[] level_11 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
//            Su[] sus_11 = new Su[11];
//            String[] S0_11 = new String[number];
//            for (int i = 22; i < accessTree_11.length; i++) {
//                String att = "A" + i;
//                S0_11[i - 22] = att;
//            }
//            String[][] S_11 = {{"A22"}, {"A23"}, {"A24"}, {"A25"}, {"A26"}, {"A27", "A28"}, {"A29", "A30"},
//                    {"A31", "A32"}, {"A33"}, {"A34"}, last_att_11};
//
//            Node[] accessTree_12 = new Node[number + 24];
//            accessTree_12[0] = new Node(new int[]{8, 8}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}, {12},
//                    {13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}, 0);
//            accessTree_12[1] = new Node(new int[]{1, 1}, new int[][]{{24}}, 1);
//            accessTree_12[2] = new Node(new int[]{1, 1}, new int[][]{{25}}, 2);
//            accessTree_12[3] = new Node(new int[]{1, 1}, new int[][]{{26}}, 3);
//            accessTree_12[4] = new Node(new int[]{1, 1}, new int[][]{{27}}, 4);
//            accessTree_12[5] = new Node(new int[]{1, 1}, new int[][]{{28}}, 5);
//            accessTree_12[6] = new Node(new int[]{1, 1}, new int[][]{{29}}, 6);
//            accessTree_12[7] = new Node(new int[]{2, 2}, new int[][]{{30}, {31}}, 7);
//            accessTree_12[8] = new Node(new int[]{2, 2}, new int[][]{{32}, {33}}, 8);
//            accessTree_12[9] = new Node(new int[]{1, 1}, new int[][]{{34}}, 9);
//            accessTree_12[10] = new Node(new int[]{1, 1}, new int[][]{{35}}, 10);
//            accessTree_12[11] = new Node(new int[]{1, 1}, new int[][]{{36}}, 11);
//            int[][] last_node_12 = new int[number - 13][1];
//            String[] last_att_12 = new String[number - 13];
//            for (int i = 37; i < accessTree_12.length; i++) {
//                last_node_12[i - 37][0] = i;
//                last_att_12[i - 37] = "A" + i;
//            }
//            accessTree_12[12] = new Node(new int[]{1, 1}, last_node_12, 12);
//            for (int i = 13; i < 24; i++) {
//                String att = "S";
//                accessTree_12[i] = new Node(att, 11, i);
//            }
//            for (int i = 24; i < accessTree_12.length; i++) {
//                String att = "A" + i;
//                accessTree_12[i] = new Node(att, 1, i);
//            }
//            int[] level_12 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
//            Su[] sus_12 = new Su[12];
//            String[] S0_12 = new String[number];
//            for (int i = 24; i < accessTree_12.length; i++) {
//                String att = "A" + i;
//                S0_12[i - 24] = att;
//            }
//            String[][] S_12 = {{"A24"}, {"A25"}, {"A26"}, {"A27"}, {"A28"}, {"A29"}, {"A30", "A31"},
//                    {"A32", "A33"}, {"A34"}, {"A35"}, {"A36"}, last_att_12};
//
//            Node[] accessTree_13 = new Node[number + 26];
//            accessTree_13[0] = new Node(new int[]{8, 8}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}, {12}, {13},
//                    {14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25}}, 0);
//            accessTree_13[1] = new Node(new int[]{1, 1}, new int[][]{{26}}, 1);
//            accessTree_13[2] = new Node(new int[]{1, 1}, new int[][]{{27}}, 2);
//            accessTree_13[3] = new Node(new int[]{1, 1}, new int[][]{{28}}, 3);
//            accessTree_13[4] = new Node(new int[]{1, 1}, new int[][]{{29}}, 4);
//            accessTree_13[5] = new Node(new int[]{1, 1}, new int[][]{{30}}, 5);
//            accessTree_13[6] = new Node(new int[]{1, 1}, new int[][]{{31}}, 6);
//            accessTree_13[7] = new Node(new int[]{1, 1}, new int[][]{{32}}, 7);
//            accessTree_13[8] = new Node(new int[]{2, 2}, new int[][]{{33}, {34}}, 8);
//            accessTree_13[9] = new Node(new int[]{1, 1}, new int[][]{{35}}, 9);
//            accessTree_13[10] = new Node(new int[]{1, 1}, new int[][]{{36}}, 10);
//            accessTree_13[11] = new Node(new int[]{1, 1}, new int[][]{{37}}, 11);
//            accessTree_13[12] = new Node(new int[]{1, 1}, new int[][]{{38}}, 12);
//            int[][] last_node_13 = new int[number - 13][1];
//            String[] last_att_13 = new String[number - 13];
//            for (int i = 39; i < accessTree_13.length; i++) {
//                last_node_13[i - 39][0] = i;
//                last_att_13[i - 39] = "A" + i;
//            }
//            accessTree_13[13] = new Node(new int[]{1, 1}, last_node_13, 13);
//            for (int i = 14; i < 26; i++) {
//                String att = "S";
//                accessTree_13[i] = new Node(att, 12, i);
//            }
//            for (int i = 26; i < accessTree_13.length; i++) {
//                String att = "A" + i;
//                accessTree_13[i] = new Node(att, 1, i);
//            }
//            int[] level_13 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
//            Su[] sus_13 = new Su[13];
//            String[] S0_13 = new String[number];
//            for (int i = 26; i < accessTree_13.length; i++) {
//                String att = "A" + i;
//                S0_13[i - 26] = att;
//            }
//            String[][] S_13 = {{"A26"}, {"A27"}, {"A28"}, {"A29"}, {"A30"}, {"A31"}, {"A32"}, {"A33", "A34"},
//                    {"A35"}, {"A36"}, {"A37"}, {"A38"}, last_att_13};
//
//            Node[] accessTree_14 = new Node[number + 28];
//            accessTree_14[0] = new Node(new int[]{8, 8}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}, {12}, {13}, {14},
//                    {15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}}, 0);
//            accessTree_14[1] = new Node(new int[]{1, 1}, new int[][]{{28}}, 1);
//            accessTree_14[2] = new Node(new int[]{1, 1}, new int[][]{{29}}, 2);
//            accessTree_14[3] = new Node(new int[]{1, 1}, new int[][]{{30}}, 3);
//            accessTree_14[4] = new Node(new int[]{1, 1}, new int[][]{{31}}, 4);
//            accessTree_14[5] = new Node(new int[]{1, 1}, new int[][]{{32}}, 5);
//            accessTree_14[6] = new Node(new int[]{1, 1}, new int[][]{{33}}, 6);
//            accessTree_14[7] = new Node(new int[]{1, 1}, new int[][]{{34}}, 7);
//            accessTree_14[8] = new Node(new int[]{1, 1}, new int[][]{{35}}, 8);
//            accessTree_14[9] = new Node(new int[]{1, 1}, new int[][]{{36}}, 9);
//            accessTree_14[10] = new Node(new int[]{1, 1}, new int[][]{{37}}, 10);
//            accessTree_14[11] = new Node(new int[]{1, 1}, new int[][]{{38}}, 11);
//            accessTree_14[12] = new Node(new int[]{1, 1}, new int[][]{{39}}, 12);
//            accessTree_14[13] = new Node(new int[]{1, 1}, new int[][]{{40}}, 13);
//            int[][] last_node_14 = new int[number - 13][1];
//            String[] last_att_14 = new String[number - 13];
//            for (int i = 41; i < accessTree_14.length; i++) {
//                last_node_14[i - 41][0] = i;
//                last_att_14[i - 41] = "A" + i;
//            }
//            accessTree_14[14] = new Node(new int[]{1, 1}, last_node_14, 14);
//            for (int i = 15; i < 28; i++) {
//                String att = "S";
//                accessTree_14[i] = new Node(att, 13, i);
//            }
//            for (int i = 28; i < accessTree_14.length; i++) {
//                String att = "A" + i;
//                accessTree_14[i] = new Node(att, 1, i);
//            }
//            int[] level_14 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
//            Su[] sus_14 = new Su[14];
//            String[] S0_14 = new String[number];
//            for (int i = 28; i < accessTree_14.length; i++) {
//                String att = "A" + i;
//                S0_14[i - 28] = att;
//            }
//            String[][] S_14 = {{"A28"}, {"A29"}, {"A30"}, {"A31"}, {"A32"}, {"A33"}, {"A34"}, {"A35"}, {"A36"},
//                    {"A37"}, {"A38"}, {"A39"}, {"A40"}, last_att_14};
//
//            Node[][] accessTree_n = {accessTree_0, accessTree_1, accessTree_2, accessTree_3, accessTree_4, accessTree_5,
//                    accessTree_6, accessTree_7, accessTree_8, accessTree_9, accessTree_10, accessTree_11, accessTree_12, accessTree_13, accessTree_14};
//            int[][] level_n = {level_0, level_1, level_2, level_3, level_4, level_5, level_6, level_7, level_8, level_9,
//                    level_10, level_11, level_12, level_13, level_14};
//            Su[][] sus_n = {sus_0, sus_1, sus_2, sus_3, sus_4, sus_5, sus_6, sus_7, sus_8, sus_9, sus_10, sus_11, sus_12, sus_13, sus_14};
//            String[][] S0_n = {S0_0, S0_1, S0_2, S0_3, S0_4, S0_5, S0_6, S0_7, S0_8, S0_9, S0_10, S0_11, S0_12, S0_13, S0_14};
//            String[][][] S_n = {S_0, S_1, S_2, S_3, S_4, S_5, S_6, S_7, S_8, S_9, S_10, S_11, S_12, S_13, S_14};

//            System.out.print(number+" Encryption : ");
//            for (int n = 1; n < 15; n++) {
//                accessTree = accessTree_n[n];
//                level = level_n[n];
//                sus = sus_n[n];
//                S0 = S0_n[n];
//                S = S_n[n];
//                //加密
//                for (int i = 0; i < 5; i++) {
//                    Encrypt(pairingPropertiesFileName, message, pkFileName, accessTree, ctFilename, level);
//                }
//                long encrypt_start = System.currentTimeMillis();
//                for (int i = 0; i < 10; i++) {
//                    Encrypt(pairingPropertiesFileName, message, pkFileName, accessTree, ctFilename, level);
//                }
//                System.out.print((System.currentTimeMillis() - encrypt_start) / 10 + " ");
//            }

//            System.out.print(number+" Decryption : ");
//            for(int n=1; n<15; n++) {
//                accessTree = accessTree_n[n];
//                level = level_n[n];
//                sus = sus_n[n];
//                S0 = S0_n[n];
//                S = S_n[n];
//                Encrypt(pairingPropertiesFileName, message, pkFileName, accessTree, ctFilename, level);
//                KeyGen(pairingPropertiesFileName, skFileName, pkFileName, mskFileName, S0);
//                //解密
//                for (int i = 0; i < 10; i++) {
//                    decrypt_message = Decrypt(pairingPropertiesFileName, S0, skFileName, ctFilename, accessTree);
//                }
//                long decrypt_start = System.currentTimeMillis();
//                for (int i = 0; i < 10; i++) {
//                    decrypt_message = Decrypt(pairingPropertiesFileName, S0, skFileName, ctFilename, accessTree);
//                }
//                System.out.print((System.currentTimeMillis() - decrypt_start) / 10+" ");
//            }
//
//            System.out.print(number+" C_Decryption : ");
//            for (int n=1; n<15;n++) {
//
//                accessTree = accessTree_n[n];
//                level = level_n[n];
//                sus = sus_n[n];
//                S0 = S0_n[n];
//                S = S_n[n];
//
//                Encrypt(pairingPropertiesFileName, message, pkFileName, accessTree, ctFilename, level);
//                KeyGen(pairingPropertiesFileName, skFileName, pkFileName, mskFileName, S0);
//
//                Properties sk = loadProperties(skFileName);
//
//                for (int i = 0; i < 5; i++) {
//                    Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D"))).getImmutable();
//                    for (int j = 0; j < level.length; j++) {
//                        KeyGen(pairingPropertiesFileName, skFileName, pkFileName, mskFileName, S[j]);
//                        sus[j] = Semi_Decrypt(pairingPropertiesFileName, S[j], skFileName, ctFilename, accessTree, level[j], D);
//                    }
//                    share_decrypt_message = ShareDecrypt(pairingPropertiesFileName, ctFilename, sus, D);
//                }
//
//                long time = 0;
//                for (int i = 0; i < 10; i++) {
//                    Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D"))).getImmutable();
//                    for (int j = 0; j < level.length; j++) {
//                        KeyGen(pairingPropertiesFileName, skFileName, pkFileName, mskFileName, S[j]);
//                        long collaborative_decrypt_start = System.currentTimeMillis();
//                        sus[j] = Semi_Decrypt(pairingPropertiesFileName, S[j], skFileName, ctFilename, accessTree, level[j], D);
//                        time += (System.currentTimeMillis() - collaborative_decrypt_start);
//                    }
//                    long start = System.currentTimeMillis();
//                    share_decrypt_message = ShareDecrypt(pairingPropertiesFileName, ctFilename, sus, D);
//                    time += (System.currentTimeMillis() - start);
//                }
//                System.out.print(n + " Collaborative Decryption: " + time / 10);
//            }
//
//            System.out.println();
//        }
        for (int n = 1; n < 2; n++) {
            //加密
            for (int i = 0; i < 5; i++) {
                Encrypt(pairingPropertiesFileName, message, pkFileName, accessTree, ctFilename, level);
            }
            long encrypt_start = System.currentTimeMillis();
            for (int i = 0; i < 10; i++) {
                Encrypt(pairingPropertiesFileName, message, pkFileName, accessTree, ctFilename, level);
            }
            System.out.print((System.currentTimeMillis() - encrypt_start) / 10 + " ");
        }
//        //密钥生成
//        long keygen_start = System.currentTimeMillis();
//        for(int i=0;i<1;i++){
//            KeyGen(pairingPropertiesFileName, skFileName, pkFileName, mskFileName, S0);
//        }
//        System.out.println("KeyGen: "+(System.currentTimeMillis()-keygen_start)/100);
//
//        for(int n=1; n<15; n++) {
//
//
//            Encrypt(pairingPropertiesFileName, message, pkFileName, accessTree, ctFilename, level);
//            KeyGen(pairingPropertiesFileName, skFileName, pkFileName, mskFileName, S0);
//            //解密
//            for (int i = 0; i < 10; i++) {
//                decrypt_message = Decrypt(pairingPropertiesFileName, S0, skFileName, ctFilename, accessTree);
//            }
//            long decrypt_start = System.currentTimeMillis();
//            for (int i = 0; i < 10; i++) {
//                decrypt_message = Decrypt(pairingPropertiesFileName, S0, skFileName, ctFilename, accessTree);
//            }
//            System.out.println(n+" Decrypt: " + (System.currentTimeMillis() - decrypt_start) / 10);
//        }
//
//        //合作解密
//        for (int n=1; n<15;n++) {
//
//
//            Encrypt(pairingPropertiesFileName, message, pkFileName, accessTree, ctFilename, level);
//            KeyGen(pairingPropertiesFileName, skFileName, pkFileName, mskFileName, S0);
//
//            Properties sk = loadProperties(skFileName);
//
//            for (int i = 0; i < 5; i++) {
//                Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D"))).getImmutable();
//                for (int j = 0; j < level.length; j++) {
//                    KeyGen(pairingPropertiesFileName, skFileName, pkFileName, mskFileName, S[j]);
//                    sus[j] = Semi_Decrypt(pairingPropertiesFileName, S[j], skFileName, ctFilename, accessTree, level[j], D);
//                }
//                share_decrypt_message = ShareDecrypt(pairingPropertiesFileName, ctFilename, sus, D);
//            }
//
//            long time = 0;
//            for (int i = 0; i < 10; i++) {
//                Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D"))).getImmutable();
//                for (int j = 0; j < level.length; j++) {
//                    KeyGen(pairingPropertiesFileName, skFileName, pkFileName, mskFileName, S[j]);
//                    long collaborative_decrypt_start = System.currentTimeMillis();
//                    sus[j] = Semi_Decrypt(pairingPropertiesFileName, S[j], skFileName, ctFilename, accessTree, level[j], D);
//                    time += (System.currentTimeMillis() - collaborative_decrypt_start);
//                }
//                long start = System.currentTimeMillis();
//                share_decrypt_message = ShareDecrypt(pairingPropertiesFileName, ctFilename, sus, D);
//                time += (System.currentTimeMillis() - start);
//            }
//            System.out.println(n+" Collaborative Decryption: " + time / 10);
//        }
//
//        System.out.println("-----------------------------");
//
//        boolean decrypt_success = decrypt_message.isEqual(test_message);
//        if (decrypt_success){
//            System.out.println("The decrypted message is " + decrypt_success + ".");
//            //System.out.println("Decrypted message is \n" + decrypt_message);
//        }
//
//        boolean collaborative_decryption_success = share_decrypt_message.isEqual(test_message);
//        if(collaborative_decryption_success) {
//            System.out.println("The share_decrypted message is " + collaborative_decryption_success + ".");
//            //System.out.println("Collaborative decrypted message is \n" + share_decrypt_message);
//        }
    }
}