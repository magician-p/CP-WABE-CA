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
import java.util.Vector;
import java.util.stream.Collectors;

public class CP_ABE_SD {

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

    public static Element[] coefficient(Vector<Integer> index, Pairing bp, Vector<Element> t_i, Element t){
        Vector<Element> index_s = new Vector<>();
        for (Integer integer : index) {
            Element index_i = bp.getZr().newElement(integer).getImmutable();
            index_s.add(index_i);
        }

        Element[][] matrix = new Element[index_s.size()][index_s.size()+1];
        int pow = index.size();
        for(int i=0;i<pow;i++){
            for(int j=0;j<pow;j++){
                matrix[i][j] = index_s.get(i).powZn(bp.getZr().newElement(pow-j)).getImmutable();
            }
            matrix[i][pow] = t_i.get(i).sub(t).getImmutable();
        }

        for(int i=0;i<pow;i++){
            for(int j=i+1;j<pow;j++){
                for(int k=0;k<=pow;k++) {
                    matrix[j][k] = matrix[j][k].add(matrix[i][k].mul(matrix[j][i].div(matrix[i][i])).negate()).getImmutable();
                }
            }
        }

        Element h = bp.getZr().newElement(1);

        for(int i=1;i<=pow;i++){
            for(int j=i+1;j<=pow;j++){
                for(int k=0;k<=pow;k++){
                    matrix[pow-j][k] = matrix[pow-j][k].add(matrix[pow-i][k].mul(matrix[pow-j][pow-i].div(matrix[pow-i][pow-i])).negate()).getImmutable();
                }
            }
        }

        for(int i=0;i<pow;i++){
            for(int j=0;j<=pow;j++){
                matrix[i][j] = matrix[i][j].mul(matrix[i][i].invert()).getImmutable();
            }
        }

        Element[] result = new Element[index.size()];
        for(int i=0;i<pow;i++){
            result[i] = matrix[i][pow].getImmutable();
        }
        return result;
    }

    public static void setup(String pairingFileName, String pkFileName, String mskFileName){
        Pairing bp = PairingFactory.getPairing(pairingFileName);
        Properties pk = new Properties();
        Properties msk = new Properties();

        Element g = bp.getG1().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();

        Element egg_beta = bp.pairing(g, g).powZn(beta).getImmutable();
        Element g_alpha = g.powZn(alpha).getImmutable();

        msk.setProperty("alpha", Base64.getEncoder().withoutPadding().encodeToString(alpha.toBytes()));
        msk.setProperty("beta", Base64.getEncoder().withoutPadding().encodeToString(beta.toBytes()));
        pk.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pk.setProperty("egg_beta", Base64.getEncoder().withoutPadding().encodeToString(egg_beta.toBytes()));
        pk.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));

        storeProperties(msk, mskFileName);
        storeProperties(pk, pkFileName);
    }

    public static void encrypt(String pairingFileName, String m, String pkFileName, String ctFileName, Node[] accessTree,
                               int levelNumber, int[] level) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFileName);

        Properties pk = loadProperties(pkFileName);

        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("g"))).getImmutable();
        Element g_alpha = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("g_alpha"))).getImmutable();
        Element egg_beta = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("egg_beta"))).getImmutable();

        //选择t与t_i
        Element t = bp.getZr().newRandomElement().getImmutable();
        Vector<Element> vector = new Vector<>();
        Element sum = bp.getZr().newZeroElement().getImmutable();
        for(int i=0;i<level.length;i++){
            Element t_i = bp.getZr().newRandomElement().getImmutable();
            vector.add(t_i);
            sum = sum.add(t_i);
        }
        vector.add(t.sub(sum));

        Element M = bp.getGT().newElementFromBytes(m.getBytes()).getImmutable();
        //Element M = hash2(m, bp).getImmutable();
        Element cv = M.mul(egg_beta.powZn(t)).getImmutable();

        //根节点，层级节点赋值
        accessTree[0].secretShare = t;
        AccessTree.nodeShare(accessTree, accessTree[0], bp);
        for(int i=0;i<level.length;i++){
            accessTree[level[i]].secretShare = vector.get(i);
        }
        //层级节点向下分发秘密
        for (int item : level) {
            AccessTree.nodeShare(accessTree, accessTree[item], bp);
        }

        //给出层级节点的编号，求系数
        Vector<Integer> index = new Vector<>();
        for (int value : level) {
            index.add(value);
        }
        Element[] coefficient = coefficient(index, bp, vector, t);

        for(int i=0;i<accessTree[1].children.length;i++){
            for(int j=0;j<accessTree[1].children[i].length;j++){
                Node node = accessTree[accessTree[1].children[i][j]];
                if(node.isLeaf()){
                    Element share = t.getImmutable();
                    for (int k=0;k<coefficient.length;k++){
                        share = share.add(coefficient[k].mul(bp.getZr().newElement(node.index).powZn(bp.getZr().newElement(coefficient.length-k))));
                    }
                    node.secretShare=share.getImmutable();
                }
            }
        }

        Properties ct = new Properties();
        for(Node node:accessTree){
            if(Arrays.stream(level).boxed().collect(Collectors.toList()).contains(node.index)){
                Element cv_i = g.powZn(node.secretShare).getImmutable();
                ct.setProperty("cv"+node.index, Base64.getEncoder().withoutPadding().encodeToString(cv_i.toBytes()));
            }
        }

        for(Node node:accessTree){
            if(node.isLeaf()){

                Element cy = g_alpha.powZn(node.secretShare).getImmutable();

                byte[] attr = hash(node.att);
                Element H = bp.getG1().newElementFromHash(attr, 0, attr.length).getImmutable();
                Element cy_1 = H.powZn(node.secretShare).getImmutable();

                ct.setProperty("cy"+node.att+node.index, Base64.getEncoder().withoutPadding().encodeToString(cy.toBytes()));
                ct.setProperty("cy_1"+node.att+node.index, Base64.getEncoder().withoutPadding().encodeToString(cy_1.toBytes()));
            }
        }
        ct.setProperty("cv", Base64.getEncoder().withoutPadding().encodeToString(cv.toBytes()));
        storeProperties(ct, ctFileName);
    }

    public static void keygen(String pairingFileName, String mskFileName, String skFileName, String pkFileName, String[] S) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFileName);

        Properties pk = loadProperties(pkFileName);
        Properties msk = loadProperties(mskFileName);

        Element r = bp.getZr().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(msk.getProperty("beta"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk.getProperty("g"))).getImmutable();
        Element D = g.powZn(beta.add(r)).getImmutable();

        Properties st = new Properties();
        for(String attr:S){
            Element r_i = bp.getZr().newRandomElement().getImmutable();
            byte[] bytes = hash(attr);
            Element H = bp.getG1().newElementFromHash(bytes, 0, bytes.length);
            Element D_j = g.powZn(r.div(alpha)).mul(H.powZn(r_i.div(alpha))).getImmutable();
            Element D_j_1 = g.powZn(r_i).getImmutable();
            st.setProperty("D_j"+attr, Base64.getEncoder().withoutPadding().encodeToString(D_j.toBytes()));
            st.setProperty("D_j_1"+attr, Base64.getEncoder().withoutPadding().encodeToString(D_j_1.toBytes()));
        }

        st.setProperty("D", Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
        storeProperties(st, skFileName);
    }

    public static Element decrypt(String pairingFileName, String[] S, String ctFileName, String skFileName, Node[] accessTree, int[] level){
        Pairing bp = PairingFactory.getPairing(pairingFileName);

        Properties ct = loadProperties(ctFileName);
        Properties sk = loadProperties(skFileName);

        Element cv = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cv"))).getImmutable();
        Element C = bp.getG1().newOneElement().getImmutable();
        for(int i:level){
            Element cv_i = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cv"+i))).getImmutable();
            C = C.mul(cv_i);
        }
        Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D"))).getImmutable();

        //计算C,D的pairing值用来消去密文附加项
        Element egg_s_beta_r = bp.pairing(C, D).getImmutable();

        for(Node node : accessTree){
            if(node.isLeaf()){
                if(Arrays.asList(S).contains(node.att)){

                    //计算每个叶节点的pairing值
                    Element c_y = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cy"+node.att+node.index))).getImmutable();
                    Element D_j = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D_j"+node.att))).getImmutable();
                    Element c_y_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cy_1"+node.att+node.index))).getImmutable();
                    Element D_j_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D_j_1"+node.att))).getImmutable();

                    node.secretShare = bp.pairing(c_y, D_j).div(bp.pairing(c_y_1, D_j_1)).getImmutable();
                }
            }
        }

        boolean treeOk = AccessTree.nodeRecover(accessTree, accessTree[0], S, bp);

        if(treeOk){
            Element egg_s_alpha = egg_s_beta_r.div(accessTree[0].secretShare).getImmutable();
            return cv.div(egg_s_alpha).getImmutable();
        }
        else {
            //System.out.println("Can't recover the tree!");
            return null;
        }
    }

    public static Element Semi_decrypt(String pairingFileName, String skFileName, String ctFileName, String[] S, Node[] accessTree, int level){
        Pairing bp = PairingFactory.getPairing(pairingFileName);

        Properties ct = loadProperties(ctFileName);
        Properties sk = loadProperties(skFileName);

        for(Node node : accessTree){
            if(node.isLeaf()){
                if(Arrays.asList(S).contains(node.att)){

                    //计算每个叶节点的pairing值
                    Element c_y = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cy"+node.att+node.index))).getImmutable();
                    Element D_j = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D_j"+node.att))).getImmutable();
                    Element c_y_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cy_1"+node.att+node.index))).getImmutable();
                    Element D_j_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D_j_1"+node.att))).getImmutable();

                    node.secretShare = bp.pairing(c_y, D_j).div(bp.pairing(c_y_1, D_j_1)).getImmutable();
                }
            }
        }
        boolean treeOk = AccessTree.nodeRecover(accessTree, accessTree[level], S, bp);
        if(treeOk){
            Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D"))).getImmutable();
            Element cv_i = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cv"+accessTree[level].index))).getImmutable();
            Element x = bp.pairing(cv_i, D).div(accessTree[level].secretShare).getImmutable();
            return x;
        }
        else {
            return null;
        }
    }
    public static void Add_op(String pairingFileName, String skFileName, String ctFileName, String[] S, Node[] accessTree, int level){
        Pairing bp = PairingFactory.getPairing(pairingFileName);

        Properties ct = loadProperties(ctFileName);
        Properties sk = loadProperties(skFileName);

        boolean treeOk = AccessTree.nodeRecover(accessTree, accessTree[level], S, bp);
        if(treeOk){
            Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk.getProperty("D"))).getImmutable();
            Element cv_i = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cv"+accessTree[level].index))).getImmutable();
            Element x = bp.pairing(cv_i, D).div(accessTree[level].secretShare).getImmutable();
        }
    }

    public static Element ShareDecrypt(String pairingPropertiesFileName, String ctFileName, Element[] sus) throws NoSuchAlgorithmException {

        Pairing bp = PairingFactory.getPairing(pairingPropertiesFileName);

        Properties ct = loadProperties(ctFileName);

        Element cv = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ct.getProperty("cv"))).getImmutable();

        //计算秘密附加项
        Element secret = bp.getGT().newOneElement().getImmutable();
        for(int i=0;i< sus.length;i++){
            secret = secret.mul(sus[i]).getImmutable();
        }

        return cv.div(secret).getImmutable();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String dir = "data/CP_ABE_SD/";

        String pairingFileName = "a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String ctFileName = dir + "ct.properties";
        String skFileName = dir + "sk.properties";

        Pairing bp = PairingFactory.getPairing(pairingFileName);
//合作节点增加
        Node[] accessTree_0 = new Node[41];
        accessTree_0[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_0[1] = new Node(new int[]{3, 3}, new int[][]{{3}, {4}, {5}}, 1);
        accessTree_0[2] = new Node(new int[]{2, 2}, new int[][]{{6}, {7}}, 2);
        accessTree_0[3] = new Node(new int[]{5, 5}, new int[][]{{8}, {9}, {10}, {11}, {12}}, 3);
        accessTree_0[4] = new Node(new int[]{5, 5}, new int[][]{{13}, {14}, {15}, {16}, {17}}, 4);
        accessTree_0[5] = new Node(new int[]{5, 5}, new int[][]{{18}, {19}, {20}, {21}, {22}}, 5);
        accessTree_0[6] = new Node(new int[]{1, 3}, new int[][]{{23}, {24}, {25}}, 7);
        accessTree_0[7] = new Node("S", 1, 7);
        accessTree_0[8] = new Node("A", 1, 8);
        accessTree_0[9] = new Node("B", 1, 9);
        accessTree_0[10] = new Node("C", 1, 10);
        accessTree_0[11] = new Node("D", 1, 11);
        accessTree_0[12] = new Node("E", 1, 12);
        accessTree_0[13] = new Node("F", 1, 13);
        accessTree_0[14] = new Node("G", 1, 14);
        accessTree_0[15] = new Node("H", 1, 15);
        accessTree_0[16] = new Node("I", 1, 16);
        accessTree_0[17] = new Node("J", 1, 17);
        accessTree_0[18] = new Node("K", 1, 18);
        accessTree_0[19] = new Node("L", 1, 19);
        accessTree_0[20] = new Node("M", 1, 20);
        accessTree_0[21] = new Node("N", 1, 21);
        accessTree_0[22] = new Node("O", 1, 22);
        accessTree_0[23] = new Node(new int[]{5, 5}, new int[][]{{26}, {27}, {28}, {29}, {30}}, 23);
        accessTree_0[24] = new Node(new int[]{5, 5}, new int[][]{{31}, {32}, {33}, {34}, {35}}, 24);
        accessTree_0[25] = new Node(new int[]{5, 5}, new int[][]{{36}, {37}, {38}, {39}, {40}}, 25);
        accessTree_0[26] = new Node("A", 1, 26);
        accessTree_0[27] = new Node("B", 1, 27);
        accessTree_0[28] = new Node("C", 1, 28);
        accessTree_0[29] = new Node("D", 1, 29);
        accessTree_0[30] = new Node("E", 1, 30);
        accessTree_0[31] = new Node("F", 1, 31);
        accessTree_0[32] = new Node("G", 1, 32);
        accessTree_0[33] = new Node("H", 1, 33);
        accessTree_0[34] = new Node("I", 1, 34);
        accessTree_0[35] = new Node("J", 1, 35);
        accessTree_0[36] = new Node("K", 1, 36);
        accessTree_0[37] = new Node("L", 1, 37);
        accessTree_0[38] = new Node("M", 1, 38);
        accessTree_0[39] = new Node("N", 1, 39);
        accessTree_0[40] = new Node("O", 1, 40);
        int[] level_0 = {3,4,5,23,24,25};
        Element[] sus_0 = new Element[3];
        String[] S0_0 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_0 = {{"A", "B", "C", "D", "E"}, {"F", "G", "H", "I", "J"}, {"K", "L", "M", "N", "O"}};

        Node[] accessTree_1 = new Node[45];
        accessTree_1[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_1[1] = new Node(new int[]{5, 5}, new int[][]{{3}, {4}, {5}, {6}, {7}}, 1);
        accessTree_1[2] = new Node(new int[]{2, 2}, new int[][]{{8}, {9}}, 2);
        accessTree_1[3] = new Node(new int[]{3, 3}, new int[][]{{10}, {11}, {12}}, 3);
        accessTree_1[4] = new Node(new int[]{3, 3}, new int[][]{{13}, {14}, {15}}, 4);
        accessTree_1[5] = new Node(new int[]{3, 3}, new int[][]{{16}, {17}, {18}}, 5);
        accessTree_1[6] = new Node(new int[]{3, 3}, new int[][]{{19}, {20}, {21}}, 6);
        accessTree_1[7] = new Node(new int[]{3, 3}, new int[][]{{22}, {23}, {24}}, 7);
        accessTree_1[8] = new Node(new int[]{1, 5}, new int[][]{{25}, {26}, {27}, {28}, {29}}, 8);
        accessTree_1[9] = new Node("S", 1, 9);
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
        accessTree_1[25] = new Node(new int[]{3, 3}, new int[][]{{30}, {31}, {32}}, 25);
        accessTree_1[26] = new Node(new int[]{3, 3}, new int[][]{{33}, {34}, {35}}, 26);
        accessTree_1[27] = new Node(new int[]{3, 3}, new int[][]{{36}, {37}, {38}}, 27);
        accessTree_1[28] = new Node(new int[]{3, 3}, new int[][]{{39}, {40}, {41}}, 28);
        accessTree_1[29] = new Node(new int[]{3, 3}, new int[][]{{42}, {43}, {44}}, 29);
        accessTree_1[30] = new Node("A", 1, 30);
        accessTree_1[31] = new Node("B", 1, 31);
        accessTree_1[32] = new Node("C", 1, 32);
        accessTree_1[33] = new Node("D", 1, 33);
        accessTree_1[34] = new Node("E", 1, 34);
        accessTree_1[35] = new Node("F", 1, 35);
        accessTree_1[36] = new Node("G", 1, 36);
        accessTree_1[37] = new Node("H", 1, 37);
        accessTree_1[38] = new Node("I", 1, 38);
        accessTree_1[39] = new Node("J", 1, 39);
        accessTree_1[40] = new Node("K", 1, 40);
        accessTree_1[41] = new Node("L", 1, 41);
        accessTree_1[42] = new Node("M", 1, 42);
        accessTree_1[43] = new Node("N", 1, 43);
        accessTree_1[44] = new Node("O", 1, 44);
        int[] level_1 = {3,4,5,6,7,25,26,27,28,29};
        Element[] sus_1 = new Element[5];
        String[] S0_1 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_1 = {{"A", "B", "C"}, {"D", "E", "F"}, {"G", "H", "I"}, {"J", "K", "L"}, {"M", "N", "O"}};

        Node[] accessTree_2 = new Node[49];
        accessTree_2[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_2[1] = new Node(new int[]{7, 7}, new int[][]{{3}, {4}, {5}, {6}, {7}, {8}, {9}}, 1);
        accessTree_2[2] = new Node(new int[]{2, 2}, new int[][]{{10}, {11}}, 2);
        accessTree_2[3] = new Node(new int[]{2, 2}, new int[][]{{12}, {13}}, 3);
        accessTree_2[4] = new Node(new int[]{2, 2}, new int[][]{{14}, {15}}, 4);
        accessTree_2[5] = new Node(new int[]{2, 2}, new int[][]{{16}, {17}}, 5);
        accessTree_2[6] = new Node(new int[]{2, 2}, new int[][]{{18}, {19}}, 6);
        accessTree_2[7] = new Node(new int[]{2, 2}, new int[][]{{20}, {21}}, 7);
        accessTree_2[8] = new Node(new int[]{2, 2}, new int[][]{{22}, {23}}, 8);
        accessTree_2[9] = new Node(new int[]{3, 3}, new int[][]{{24}, {25}, {26}}, 9);
        accessTree_2[10] = new Node(new int[]{1, 7}, new int[][]{{27}, {28}, {29}, {30}, {31}, {32}, {33}}, 10);
        accessTree_2[11] = new Node("S", 1, 11);
        accessTree_2[12] = new Node("A", 1, 10);
        accessTree_2[13] = new Node("B", 1, 11);
        accessTree_2[14] = new Node("C", 1, 12);
        accessTree_2[15] = new Node("D", 1, 13);
        accessTree_2[16] = new Node("E", 1, 14);
        accessTree_2[17] = new Node("F", 1, 15);
        accessTree_2[18] = new Node("G", 1, 16);
        accessTree_2[19] = new Node("H", 1, 17);
        accessTree_2[20] = new Node("I", 1, 20);
        accessTree_2[21] = new Node("J", 1, 21);
        accessTree_2[22] = new Node("K", 1, 22);
        accessTree_2[23] = new Node("L", 1, 23);
        accessTree_2[24] = new Node("M", 1, 24);
        accessTree_2[25] = new Node("N", 1, 25);
        accessTree_2[26] = new Node("O", 1, 26);
        accessTree_2[27] = new Node(new int[]{2, 2}, new int[][]{{34}, {35}}, 27);
        accessTree_2[28] = new Node(new int[]{2, 2}, new int[][]{{37}, {36}}, 28);
        accessTree_2[29] = new Node(new int[]{2, 2}, new int[][]{{39}, {38}}, 29);
        accessTree_2[30] = new Node(new int[]{2, 2}, new int[][]{{41}, {40}}, 30);
        accessTree_2[31] = new Node(new int[]{2, 2}, new int[][]{{43}, {42}}, 31);
        accessTree_2[32] = new Node(new int[]{2, 2}, new int[][]{{45}, {44}}, 32);
        accessTree_2[33] = new Node(new int[]{3, 3}, new int[][]{{47}, {46}, {48}}, 33);
        accessTree_2[34] = new Node("A", 1, 34);
        accessTree_2[35] = new Node("B", 1, 35);
        accessTree_2[36] = new Node("C", 1, 36);
        accessTree_2[37] = new Node("D", 1, 37);
        accessTree_2[38] = new Node("E", 1, 38);
        accessTree_2[39] = new Node("F", 1, 39);
        accessTree_2[40] = new Node("G", 1, 40);
        accessTree_2[41] = new Node("H", 1, 41);
        accessTree_2[42] = new Node("I", 1, 42);
        accessTree_2[43] = new Node("J", 1, 43);
        accessTree_2[44] = new Node("K", 1, 44);
        accessTree_2[45] = new Node("L", 1, 45);
        accessTree_2[46] = new Node("M", 1, 46);
        accessTree_2[47] = new Node("N", 1, 47);
        accessTree_2[48] = new Node("O", 1, 48);
        int[] level_2 = {3,4,5,6,7,8,9,27,28,29,30,31,32,33};
        Element[] sus_2 = new Element[7];
        String[] S0_2 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_2 = {{"A", "B"}, {"C", "D"}, {"E", "F"}, {"G", "H"}, {"I", "J"}, {"K", "L"}, {"M", "N", "O"}};

        Node[] accessTree_3 = new Node[65];
        accessTree_3[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_3[1] = new Node(new int[]{10, 10}, new int[][]{{3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}, {12}}, 1);
        accessTree_3[2] = new Node(new int[]{2, 2}, new int[][]{{13}, {14}}, 2);
        accessTree_3[3] = new Node(new int[]{2, 2}, new int[][]{{15}, {16}}, 3);
        accessTree_3[4] = new Node(new int[]{2, 2}, new int[][]{{17}, {18}}, 4);
        accessTree_3[5] = new Node(new int[]{2, 2}, new int[][]{{19}, {20}}, 5);
        accessTree_3[6] = new Node(new int[]{2, 2}, new int[][]{{21}, {22}}, 6);
        accessTree_3[7] = new Node(new int[]{2, 2}, new int[][]{{23}, {24}}, 7);
        accessTree_3[8] = new Node(new int[]{2, 2}, new int[][]{{25}, {26}}, 8);
        accessTree_3[9] = new Node(new int[]{2, 2}, new int[][]{{27}, {28}}, 9);
        accessTree_3[10] = new Node(new int[]{2, 2}, new int[][]{{29}, {30}}, 10);
        accessTree_3[11] = new Node(new int[]{2, 2}, new int[][]{{31}, {32}}, 11);
        accessTree_3[12] = new Node(new int[]{2, 2}, new int[][]{{33}, {34}}, 12);
        accessTree_3[13] = new Node(new int[]{1, 10}, new int[][]{{35}, {36}, {37}, {38}, {39}, {40}, {41}, {42}, {43}, {44}}, 13);
        accessTree_3[14] = new Node("S", 1, 14);
        accessTree_3[15] = new Node("A", 1, 15);
        accessTree_3[16] = new Node("B", 1, 16);
        accessTree_3[17] = new Node("C", 1, 17);
        accessTree_3[18] = new Node("D", 1, 18);
        accessTree_3[19] = new Node("E", 1, 19);
        accessTree_3[20] = new Node("F", 1, 20);
        accessTree_3[21] = new Node("G", 1, 21);
        accessTree_3[22] = new Node("H", 1, 22);
        accessTree_3[23] = new Node("I", 1, 23);
        accessTree_3[24] = new Node("J", 1, 24);
        accessTree_3[25] = new Node("K", 1, 25);
        accessTree_3[26] = new Node("L", 1, 26);
        accessTree_3[27] = new Node("M", 1, 27);
        accessTree_3[28] = new Node("N", 1, 28);
        accessTree_3[29] = new Node("O", 1, 29);
        accessTree_3[30] = new Node("P", 1, 30);
        accessTree_3[31] = new Node("Q", 1, 31);
        accessTree_3[32] = new Node("R", 1, 32);
        accessTree_3[33] = new Node("T", 1, 33);
        accessTree_3[34] = new Node("U", 1, 34);
        accessTree_3[35] = new Node(new int[]{2, 2}, new int[][]{{45}, {46}}, 35);
        accessTree_3[36] = new Node(new int[]{2, 2}, new int[][]{{47}, {48}}, 36);
        accessTree_3[37] = new Node(new int[]{2, 2}, new int[][]{{49}, {50}}, 37);
        accessTree_3[38] = new Node(new int[]{2, 2}, new int[][]{{51}, {52}}, 38);
        accessTree_3[39] = new Node(new int[]{2, 2}, new int[][]{{53}, {54}}, 39);
        accessTree_3[40] = new Node(new int[]{2, 2}, new int[][]{{55}, {56}}, 40);
        accessTree_3[41] = new Node(new int[]{2, 2}, new int[][]{{57}, {58}}, 41);
        accessTree_3[42] = new Node(new int[]{2, 2}, new int[][]{{59}, {60}}, 42);
        accessTree_3[43] = new Node(new int[]{2, 2}, new int[][]{{61}, {62}}, 43);
        accessTree_3[44] = new Node(new int[]{2, 2}, new int[][]{{63}, {64}}, 44);
        accessTree_3[45] = new Node("A", 1, 45);
        accessTree_3[46] = new Node("B", 1, 46);
        accessTree_3[47] = new Node("C", 1, 47);
        accessTree_3[48] = new Node("D", 1, 48);
        accessTree_3[49] = new Node("E", 1, 49);
        accessTree_3[50] = new Node("F", 1, 50);
        accessTree_3[51] = new Node("G", 1, 51);
        accessTree_3[52] = new Node("H", 1, 52);
        accessTree_3[53] = new Node("I", 1, 53);
        accessTree_3[54] = new Node("J", 1, 54);
        accessTree_3[55] = new Node("K", 1, 55);
        accessTree_3[56] = new Node("L", 1, 56);
        accessTree_3[57] = new Node("M", 1, 57);
        accessTree_3[58] = new Node("N", 1, 58);
        accessTree_3[59] = new Node("O", 1, 59);
        accessTree_3[60] = new Node("P", 1, 60);
        accessTree_3[61] = new Node("Q", 1, 61);
        accessTree_3[62] = new Node("R", 1, 62);
        accessTree_3[63] = new Node("T", 1, 63);
        accessTree_3[64] = new Node("U", 1, 64);
        int[] level_3 = {3,4,5,6,7,8,9,10,11,12,35,36,37,38,39,40,41,42,43,44};
        Element[] sus_3 = new Element[10];
        String[] S0_3 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "T", "U"};
        String[][] S_3 = {{"A", "B"}, {"C", "D"}, {"E", "F"}, {"G", "H"}, {"I", "J"}, {"K", "L"}, {"M", "N"}, {"O", "P"}, {"Q", "R"}, {"T", "U"}};

        Node[] accessTree_4 = new Node[45];
        accessTree_4[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_4[1] = new Node(new int[]{5, 5}, new int[][]{{3}, {4}, {5}, {6}, {7}}, 1);
        accessTree_4[2] = new Node(new int[]{2, 2}, new int[][]{{8}, {9}}, 2);
        accessTree_4[3] = new Node(new int[]{3, 3}, new int[][]{{10}, {11}, {12}}, 3);
        accessTree_4[4] = new Node(new int[]{3, 3}, new int[][]{{13}, {14}, {15}}, 4);
        accessTree_4[5] = new Node(new int[]{3, 3}, new int[][]{{16}, {17}, {18}}, 5);
        accessTree_4[6] = new Node(new int[]{3, 3}, new int[][]{{19}, {20}, {21}}, 6);
        accessTree_4[7] = new Node(new int[]{3, 3}, new int[][]{{22}, {23}, {24}}, 7);
        accessTree_4[8] = new Node(new int[]{1, 5}, new int[][]{{25}, {26}, {27}, {28}, {29}}, 8);
        accessTree_4[9] = new Node("S", 1, 9);
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
        accessTree_4[25] = new Node(new int[]{3, 3}, new int[][]{{30}, {31}, {32}}, 25);
        accessTree_4[26] = new Node(new int[]{3, 3}, new int[][]{{33}, {34}, {35}}, 26);
        accessTree_4[27] = new Node(new int[]{3, 3}, new int[][]{{36}, {37}, {38}}, 27);
        accessTree_4[28] = new Node(new int[]{3, 3}, new int[][]{{39}, {40}, {41}}, 28);
        accessTree_4[29] = new Node(new int[]{3, 3}, new int[][]{{42}, {43}, {44}}, 29);
        accessTree_4[30] = new Node("A", 1, 30);
        accessTree_4[31] = new Node("B", 1, 31);
        accessTree_4[32] = new Node("C", 1, 32);
        accessTree_4[33] = new Node("D", 1, 33);
        accessTree_4[34] = new Node("E", 1, 34);
        accessTree_4[35] = new Node("F", 1, 35);
        accessTree_4[36] = new Node("G", 1, 36);
        accessTree_4[37] = new Node("H", 1, 37);
        accessTree_4[38] = new Node("I", 1, 38);
        accessTree_4[39] = new Node("J", 1, 39);
        accessTree_4[40] = new Node("K", 1, 40);
        accessTree_4[41] = new Node("L", 1, 41);
        accessTree_4[42] = new Node("M", 1, 42);
        accessTree_4[43] = new Node("N", 1, 43);
        accessTree_4[44] = new Node("O", 1, 44);
        int[] level_4 = {3,4,5,6,7,25,26,27,28,29};
        Element[] sus_4 = new Element[5];
        String[] S0_4 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_4 = {{"A", "B", "C"}, {"D", "E", "F"}, {"G", "H", "I"}, {"J", "K", "L"}, {"M", "N", "O"}};

        Node[] accessTree_5 = new Node[55];
        accessTree_5[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_5[1] = new Node(new int[]{5, 5}, new int[][]{{3}, {4}, {5}, {6}, {7}}, 1);
        accessTree_5[2] = new Node(new int[]{2, 2}, new int[][]{{8}, {9}}, 2);
        accessTree_5[3] = new Node(new int[]{4, 4}, new int[][]{{10}, {11}, {12}, {13}}, 3);
        accessTree_5[4] = new Node(new int[]{4, 4}, new int[][]{{14}, {15}, {16}, {17}}, 4);
        accessTree_5[5] = new Node(new int[]{4, 4}, new int[][]{{18}, {19}, {20}, {21}}, 5);
        accessTree_5[6] = new Node(new int[]{4, 4}, new int[][]{{22}, {23}, {24}, {25}}, 6);
        accessTree_5[7] = new Node(new int[]{4, 4}, new int[][]{{26}, {27}, {28}, {29}}, 7);
        accessTree_5[8] = new Node(new int[]{1, 5}, new int[][]{{30}, {31}, {32}, {33}, {34}}, 8);
        accessTree_5[9] = new Node("S", 1, 9);
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
        accessTree_5[30] = new Node(new int[]{4, 4}, new int[][]{{35}, {36}, {37}, {38}}, 30);
        accessTree_5[31] = new Node(new int[]{4, 4}, new int[][]{{39}, {40}, {41}, {42}}, 31);
        accessTree_5[32] = new Node(new int[]{4, 4}, new int[][]{{43}, {44}, {45}, {46}}, 32);
        accessTree_5[33] = new Node(new int[]{4, 4}, new int[][]{{47}, {48}, {49}, {50}}, 33);
        accessTree_5[34] = new Node(new int[]{4, 4}, new int[][]{{51}, {52}, {53}, {54}}, 34);
        accessTree_5[35] = new Node("A", 1, 35);
        accessTree_5[36] = new Node("B", 1, 36);
        accessTree_5[37] = new Node("C", 1, 37);
        accessTree_5[38] = new Node("D", 1, 38);
        accessTree_5[39] = new Node("E", 1, 39);
        accessTree_5[40] = new Node("F", 1, 40);
        accessTree_5[41] = new Node("G", 1, 41);
        accessTree_5[42] = new Node("H", 1, 42);
        accessTree_5[43] = new Node("I", 1, 43);
        accessTree_5[44] = new Node("J", 1, 44);
        accessTree_5[45] = new Node("K", 1, 45);
        accessTree_5[46] = new Node("L", 1, 46);
        accessTree_5[47] = new Node("M", 1, 47);
        accessTree_5[48] = new Node("N", 1, 48);
        accessTree_5[49] = new Node("O", 1, 49);
        accessTree_5[50] = new Node("P", 1, 50);
        accessTree_5[51] = new Node("Q", 1, 51);
        accessTree_5[52] = new Node("R", 1, 52);
        accessTree_5[53] = new Node("T", 1, 53);
        accessTree_5[54] = new Node("U", 1, 54);
        int[] level_5 = {3,4,5,6,7,30,31,32,33,34};
        Element[] sus_5 = new Element[5];
        String[] S0_5 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "T", "U"};
        String[][] S_5 = {{"A", "B", "C", "D"}, {"E", "F", "G", "H"}, {"I", "J", "K", "L"}, {"M", "N", "O", "P"}, {"Q", "R", "T", "U"}};

        Node[] accessTree_6 = new Node[65];
        accessTree_6[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_6[1] = new Node(new int[]{5, 5}, new int[][]{{3}, {4}, {5}, {6}, {7}}, 1);
        accessTree_6[2] = new Node(new int[]{2, 2}, new int[][]{{8}, {9}}, 2);
        accessTree_6[3] = new Node(new int[]{5, 5}, new int[][]{{10}, {11}, {12}, {13}, {14}}, 3);
        accessTree_6[4] = new Node(new int[]{5, 5}, new int[][]{{15}, {16}, {17}, {18}, {19}}, 4);
        accessTree_6[5] = new Node(new int[]{5, 5}, new int[][]{{20}, {21}, {22}, {23}, {24}}, 5);
        accessTree_6[6] = new Node(new int[]{5, 5}, new int[][]{{25}, {26}, {27}, {28}, {29}}, 6);
        accessTree_6[7] = new Node(new int[]{5, 5}, new int[][]{{30}, {31}, {32}, {33}, {34}}, 7);
        accessTree_6[8] = new Node(new int[]{1, 5}, new int[][]{{35}, {36}, {37}, {38}, {39}}, 8);
        accessTree_6[9] = new Node("S", 1, 9);
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
        accessTree_6[35] = new Node(new int[]{5, 5}, new int[][]{{40}, {41}, {42}, {43}, {44}}, 35);
        accessTree_6[36] = new Node(new int[]{5, 5}, new int[][]{{45}, {46}, {47}, {48}, {49}}, 36);
        accessTree_6[37] = new Node(new int[]{5, 5}, new int[][]{{50}, {51}, {52}, {53}, {54}}, 37);
        accessTree_6[38] = new Node(new int[]{5, 5}, new int[][]{{55}, {56}, {57}, {58}, {59}}, 38);
        accessTree_6[39] = new Node(new int[]{5, 5}, new int[][]{{60}, {61}, {62}, {63}, {64}}, 39);
        accessTree_6[40] = new Node("A", 1, 40);
        accessTree_6[41] = new Node("B", 1, 41);
        accessTree_6[42] = new Node("C", 1, 42);
        accessTree_6[43] = new Node("D", 1, 43);
        accessTree_6[44] = new Node("E", 1, 44);
        accessTree_6[45] = new Node("F", 1, 45);
        accessTree_6[46] = new Node("G", 1, 46);
        accessTree_6[47] = new Node("H", 1, 47);
        accessTree_6[48] = new Node("I", 1, 48);
        accessTree_6[49] = new Node("J", 1, 49);
        accessTree_6[50] = new Node("K", 1, 50);
        accessTree_6[51] = new Node("L", 1, 51);
        accessTree_6[52] = new Node("M", 1, 52);
        accessTree_6[53] = new Node("N", 1, 53);
        accessTree_6[54] = new Node("O", 1, 54);
        accessTree_6[55] = new Node("P", 1, 55);
        accessTree_6[56] = new Node("Q", 1, 56);
        accessTree_6[57] = new Node("R", 1, 57);
        accessTree_6[58] = new Node("T", 1, 58);
        accessTree_6[59] = new Node("U", 1, 59);
        accessTree_6[60] = new Node("V", 1, 60);
        accessTree_6[61] = new Node("W", 1, 61);
        accessTree_6[62] = new Node("X", 1, 62);
        accessTree_6[63] = new Node("Y", 1, 63);
        accessTree_6[64] = new Node("Z", 1, 64);
        int[] level_6 = {3,4,5,6,7,35,36,37,38,39};
        Element[] sus_6 = new Element[5];
        String[] S0_6 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "T",
                "U", "V", "W", "X", "Y", "Z"};
        String[][] S_6 = {{"A", "B", "C", "D", "E"}, {"F", "G", "H", "I", "J"}, {"K", "L", "M", "N", "O"},
                {"P", "Q", "R", "T", "U"}, {"V", "W", "X", "Y", "Z"}};

        Node[] accessTree_7 = new Node[75];
        accessTree_7[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_7[1] = new Node(new int[]{5, 5}, new int[][]{{3}, {4}, {5}, {6}, {7}}, 1);
        accessTree_7[2] = new Node(new int[]{2, 2}, new int[][]{{8}, {9}}, 2);
        accessTree_7[3] = new Node(new int[]{6, 6}, new int[][]{{10}, {11}, {12}, {13}, {14}, {15}}, 3);
        accessTree_7[4] = new Node(new int[]{6, 6}, new int[][]{{16}, {17}, {18}, {19}, {20}, {21}}, 4);
        accessTree_7[5] = new Node(new int[]{6, 6}, new int[][]{{22}, {23}, {24}, {25}, {26}, {27}}, 5);
        accessTree_7[6] = new Node(new int[]{6, 6}, new int[][]{{28}, {29}, {30}, {31}, {32}, {33}}, 6);
        accessTree_7[7] = new Node(new int[]{6, 6}, new int[][]{{34}, {35}, {36}, {37}, {38}, {39}}, 7);
        accessTree_7[8] = new Node(new int[]{1, 5}, new int[][]{{40}, {41}, {42}, {43}, {44}, {45}}, 8);
        accessTree_7[9] = new Node("S", 1, 9);
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
        accessTree_7[40] = new Node(new int[]{6, 6}, new int[][]{{45}, {46}, {47}, {48}, {49}, {50}}, 40);
        accessTree_7[41] = new Node(new int[]{6, 6}, new int[][]{{51}, {52}, {53}, {54}, {55}, {56}}, 41);
        accessTree_7[42] = new Node(new int[]{6, 6}, new int[][]{{57}, {58}, {59}, {60}, {61}, {62}}, 42);
        accessTree_7[43] = new Node(new int[]{6, 6}, new int[][]{{63}, {64}, {65}, {66}, {67}, {68}}, 43);
        accessTree_7[44] = new Node(new int[]{6, 6}, new int[][]{{69}, {70}, {71}, {72}, {73}, {74}}, 44);
        accessTree_7[45] = new Node("A", 1, 45);
        accessTree_7[46] = new Node("B", 1, 46);
        accessTree_7[47] = new Node("C", 1, 47);
        accessTree_7[48] = new Node("D", 1, 48);
        accessTree_7[49] = new Node("E", 1, 49);
        accessTree_7[50] = new Node("F", 1, 50);
        accessTree_7[51] = new Node("G", 1, 51);
        accessTree_7[52] = new Node("H", 1, 52);
        accessTree_7[53] = new Node("I", 1, 53);
        accessTree_7[54] = new Node("J", 1, 54);
        accessTree_7[55] = new Node("K", 1, 55);
        accessTree_7[56] = new Node("L", 1, 56);
        accessTree_7[57] = new Node("M", 1, 57);
        accessTree_7[58] = new Node("N", 1, 58);
        accessTree_7[59] = new Node("O", 1, 59);
        accessTree_7[60] = new Node("P", 1, 60);
        accessTree_7[61] = new Node("Q", 1, 61);
        accessTree_7[62] = new Node("R", 1, 62);
        accessTree_7[63] = new Node("T", 1, 63);
        accessTree_7[64] = new Node("U", 1, 64);
        accessTree_7[65] = new Node("V", 1, 65);
        accessTree_7[66] = new Node("W", 1, 66);
        accessTree_7[67] = new Node("X", 1, 67);
        accessTree_7[68] = new Node("Y", 1, 68);
        accessTree_7[69] = new Node("Z", 1, 69);
        accessTree_7[70] = new Node("A1", 1, 70);
        accessTree_7[71] = new Node("A2", 1, 71);
        accessTree_7[72] = new Node("A3", 1, 72);
        accessTree_7[73] = new Node("A4", 1, 73);
        accessTree_7[74] = new Node("A5", 1, 74);
        int[] level_7 = {3,4,5,6,7,40,41,42,43,44};
        Element[] sus_7 = new Element[5];
        String[] S0_7 = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "T",
                "U", "V", "W", "X", "Y", "Z", "A1", "A2", "A3", "A4", "A5"};
        String[][] S_7 = {{"A", "B", "C", "D", "E", "F"}, {"G", "H", "I", "J", "K", "L"}, {"M", "N", "O", "P", "Q", "R"},
                {"T", "U", "V", "W", "X", "Y"}, {"Z", "A1", "A2", "A3", "A4", "A5"}};

        Node[] accessTree_xx = new Node[53];
        accessTree_xx[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_xx[1] = new Node(new int[]{9, 9}, new int[][]{{3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}}, 1);
        accessTree_xx[2] = new Node(new int[]{2, 2}, new int[][]{{12}, {13}}, 2);
        accessTree_xx[3] = new Node(new int[]{2, 2}, new int[][]{{15}, {14}}, 3);
        accessTree_xx[4] = new Node(new int[]{2, 2}, new int[][]{{17}, {16}}, 4);
        accessTree_xx[5] = new Node(new int[]{2, 2}, new int[][]{{19}, {18}}, 5);
        accessTree_xx[6] = new Node(new int[]{2, 2}, new int[][]{{21}, {20}}, 6);
        accessTree_xx[7] = new Node(new int[]{2, 2}, new int[][]{{23}, {22}}, 7);
        accessTree_xx[8] = new Node(new int[]{1, 1}, new int[][]{{24}}, 8);
        accessTree_xx[9] = new Node(new int[]{1, 1}, new int[][]{{25}}, 9);
        accessTree_xx[10] = new Node(new int[]{1, 1}, new int[][]{{26}}, 10);
        accessTree_xx[11] = new Node(new int[]{2, 2}, new int[][]{{27}, {28}}, 11);
        accessTree_xx[12] = new Node(new int[]{1, 9}, new int[][]{{29}, {30}, {31}, {32}, {33}, {34}, {35}, {36}, {37}}, 12);
        accessTree_xx[13] = new Node("S", 1, 13);
        accessTree_xx[14] = new Node("A", 1, 14);
        accessTree_xx[15] = new Node("B", 1, 15);
        accessTree_xx[16] = new Node("C", 1, 16);
        accessTree_xx[17] = new Node("D", 1, 17);
        accessTree_xx[18] = new Node("E", 1, 18);
        accessTree_xx[19] = new Node("F", 1, 19);
        accessTree_xx[20] = new Node("G", 1, 20);
        accessTree_xx[21] = new Node("H", 1, 21);
        accessTree_xx[22] = new Node("I", 1, 22);
        accessTree_xx[23] = new Node("J", 1, 23);
        accessTree_xx[24] = new Node("K", 1, 24);
        accessTree_xx[25] = new Node("L", 1, 25);
        accessTree_xx[26] = new Node("M", 1, 26);
        accessTree_xx[27] = new Node("N", 1, 27);
        accessTree_xx[28] = new Node("O", 1, 28);
        accessTree_xx[29] = new Node(new int[]{2, 2}, new int[][]{{38}, {39}}, 29);
        accessTree_xx[30] = new Node(new int[]{2, 2}, new int[][]{{40}, {41}}, 30);
        accessTree_xx[31] = new Node(new int[]{2, 2}, new int[][]{{42}, {43}}, 31);
        accessTree_xx[32] = new Node(new int[]{2, 2}, new int[][]{{44}, {45}}, 32);
        accessTree_xx[33] = new Node(new int[]{2, 2}, new int[][]{{46}, {47}}, 33);
        accessTree_xx[34] = new Node(new int[]{1, 1}, new int[][]{{48}}, 34);
        accessTree_xx[35] = new Node(new int[]{1, 1}, new int[][]{{49}}, 35);
        accessTree_xx[36] = new Node(new int[]{1, 1}, new int[][]{{50}}, 36);
        accessTree_xx[37] = new Node(new int[]{2, 2}, new int[][]{{51}, {52}}, 37);
        accessTree_xx[38] = new Node("A", 1, 38);
        accessTree_xx[39] = new Node("B", 1, 39);
        accessTree_xx[40] = new Node("C", 1, 40);
        accessTree_xx[41] = new Node("D", 1, 41);
        accessTree_xx[42] = new Node("E", 1, 42);
        accessTree_xx[43] = new Node("F", 1, 43);
        accessTree_xx[44] = new Node("G", 1, 44);
        accessTree_xx[45] = new Node("H", 1, 45);
        accessTree_xx[46] = new Node("I", 1, 46);
        accessTree_xx[47] = new Node("J", 1, 47);
        accessTree_xx[48] = new Node("K", 1, 48);
        accessTree_xx[49] = new Node("L", 1, 49);
        accessTree_xx[50] = new Node("M", 1, 50);
        accessTree_xx[51] = new Node("N", 1, 51);
        accessTree_xx[52] = new Node("O", 1, 52);
        int[] level_xx = {3,4,5,6,7,8,9,10,11,29,30,31,32,33,34,35,36,37};
        Element[] sus_xx = new Element[9];
        String[] S0_xx = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O"};
        String[][] S_xx = {{"A", "B"}, {"C", "D"}, {"E", "F"}, {"G", "H"}, {"I", "J"}, {"K"}, {"L"}, {"M"}, {"N", "O"}};

        Node[] accessTree_3_X = new Node[17];
        accessTree_3_X[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_3_X[1] = new Node(new int[]{3, 3}, new int[][]{{3}, {4}, {5}}, 1);
        accessTree_3_X[2] = new Node(new int[]{2, 2}, new int[][]{{6}, {7}}, 2);
        accessTree_3_X[3] = new Node(new int[]{1, 1}, new int[][]{{8}}, 3);
        accessTree_3_X[4] = new Node(new int[]{1, 1}, new int[][]{{9}}, 4);
        accessTree_3_X[5] = new Node(new int[]{1, 1}, new int[][]{{10}}, 5);
        accessTree_3_X[6] = new Node(new int[]{1, 3}, new int[][]{{11}, {12}, {13}}, 7);
        accessTree_3_X[7] = new Node("S", 1, 7);
        accessTree_3_X[8] = new Node("A", 1, 8);
        accessTree_3_X[9] = new Node("B", 1, 9);
        accessTree_3_X[10] = new Node("C", 1, 10);
        accessTree_3_X[11] = new Node(new int[]{1, 1}, new int[][]{{14}}, 11);
        accessTree_3_X[12] = new Node(new int[]{1, 1}, new int[][]{{15}}, 12);
        accessTree_3_X[13] = new Node(new int[]{1, 1}, new int[][]{{16}}, 13);
        accessTree_3_X[14] = new Node("A", 1, 14);
        accessTree_3_X[15] = new Node("B", 1, 15);
        accessTree_3_X[16] = new Node("C", 1, 16);
        int[] level_3_x = {3,4,5,11,12,13};
        Element[] sus_3_x = new Element[3];
        String[] S0_3_x = {"A", "B", "C"};
        String[][] S_3_x = {{"A"}, {"B"}, {"C"}};

        Node[] accessTree_5_x = new Node[25];
        accessTree_5_x[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_5_x[1] = new Node(new int[]{5, 5}, new int[][]{{3}, {4}, {5}, {6}, {7}}, 1);
        accessTree_5_x[2] = new Node(new int[]{2, 2}, new int[][]{{8}, {9}}, 2);
        accessTree_5_x[3] = new Node(new int[]{1, 1}, new int[][]{{10}}, 3);
        accessTree_5_x[4] = new Node(new int[]{1, 1}, new int[][]{{11}}, 4);
        accessTree_5_x[5] = new Node(new int[]{1, 1}, new int[][]{{12}}, 5);
        accessTree_5_x[6] = new Node(new int[]{1, 1}, new int[][]{{13}}, 6);
        accessTree_5_x[7] = new Node(new int[]{1, 1}, new int[][]{{14}}, 7);
        accessTree_5_x[8] = new Node(new int[]{1, 5}, new int[][]{{15}, {16}, {17}, {18}, {19}}, 8);
        accessTree_5_x[9] = new Node("S", 1, 9);
        accessTree_5_x[10] = new Node("A", 1, 10);
        accessTree_5_x[11] = new Node("B", 1, 11);
        accessTree_5_x[12] = new Node("C", 1, 12);
        accessTree_5_x[13] = new Node("D", 1, 13);
        accessTree_5_x[14] = new Node("E", 1, 14);
        accessTree_5_x[15] = new Node(new int[]{1, 1}, new int[][]{{20}}, 15);
        accessTree_5_x[16] = new Node(new int[]{1, 1}, new int[][]{{21}}, 16);
        accessTree_5_x[17] = new Node(new int[]{1, 1}, new int[][]{{22}}, 17);
        accessTree_5_x[18] = new Node(new int[]{1, 1}, new int[][]{{23}}, 18);
        accessTree_5_x[19] = new Node(new int[]{1, 1}, new int[][]{{24}}, 19);
        accessTree_5_x[20] = new Node("A", 1, 20);
        accessTree_5_x[21] = new Node("B", 1, 21);
        accessTree_5_x[22] = new Node("C", 1, 22);
        accessTree_5_x[23] = new Node("D", 1, 23);
        accessTree_5_x[24] = new Node("E", 1, 24);
        int[] level_5_x = {3,4,5,6,7,15,16,17,18,19};
        Element[] sus_5_x = new Element[5];
        String[] S0_5_x = {"A", "B", "C", "D", "E"};
        String[][] S_5_x = {{"A"}, {"B"}, {"C"}, {"D"}, {"E"}};

        Node[] accessTree_7_x = new Node[33];
        accessTree_7_x[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_7_x[1] = new Node(new int[]{7, 7}, new int[][]{{3}, {4}, {5}, {6}, {7}, {8}, {9}}, 1);
        accessTree_7_x[2] = new Node(new int[]{2, 2}, new int[][]{{10}, {11}}, 2);
        accessTree_7_x[3] = new Node(new int[]{1, 1}, new int[][]{{12}}, 3);
        accessTree_7_x[4] = new Node(new int[]{1, 1}, new int[][]{{13}}, 4);
        accessTree_7_x[5] = new Node(new int[]{1, 1}, new int[][]{{14}}, 5);
        accessTree_7_x[6] = new Node(new int[]{1, 1}, new int[][]{{15}}, 6);
        accessTree_7_x[7] = new Node(new int[]{1, 1}, new int[][]{{16}}, 7);
        accessTree_7_x[8] = new Node(new int[]{1, 1}, new int[][]{{17}}, 8);
        accessTree_7_x[9] = new Node(new int[]{1, 1}, new int[][]{{18}}, 9);
        accessTree_7_x[10] = new Node(new int[]{1, 7}, new int[][]{{19}, {20}, {21}, {22}, {23}, {24}, {25}}, 10);
        accessTree_7_x[11] = new Node("S", 1, 11);
        accessTree_7_x[12] = new Node("A", 1, 10);
        accessTree_7_x[13] = new Node("B", 1, 11);
        accessTree_7_x[14] = new Node("C", 1, 12);
        accessTree_7_x[15] = new Node("D", 1, 13);
        accessTree_7_x[16] = new Node("E", 1, 14);
        accessTree_7_x[17] = new Node("F", 1, 15);
        accessTree_7_x[18] = new Node("G", 1, 16);
        accessTree_7_x[19] = new Node(new int[]{1, 1}, new int[][]{{26}}, 19);
        accessTree_7_x[20] = new Node(new int[]{1, 1}, new int[][]{{27}}, 20);
        accessTree_7_x[21] = new Node(new int[]{1, 1}, new int[][]{{28}}, 21);
        accessTree_7_x[22] = new Node(new int[]{1, 1}, new int[][]{{29}}, 22);
        accessTree_7_x[23] = new Node(new int[]{1, 1}, new int[][]{{30}}, 23);
        accessTree_7_x[24] = new Node(new int[]{1, 1}, new int[][]{{31}}, 24);
        accessTree_7_x[25] = new Node(new int[]{1, 1}, new int[][]{{32}}, 25);
        accessTree_7_x[26] = new Node("A", 1, 26);
        accessTree_7_x[27] = new Node("B", 1, 27);
        accessTree_7_x[28] = new Node("C", 1, 28);
        accessTree_7_x[29] = new Node("D", 1, 29);
        accessTree_7_x[30] = new Node("E", 1, 30);
        accessTree_7_x[31] = new Node("F", 1, 31);
        accessTree_7_x[32] = new Node("G", 1, 32);
        int[] level_7_x = {3,4,5,6,7,8,9,19,20,21,22,23,24,25};
        Element[] sus_7_x = new Element[7];
        String[] S0_7_x = {"A", "B", "C", "D", "E", "F", "G"};
        String[][] S_7_x = {{"A"}, {"B"}, {"C"}, {"D"}, {"E"}, {"F"}, {"G"}};

        Node[] accessTree_9_x = new Node[41];
        accessTree_9_x[0] = new Node(new int[]{1, 2}, new int[][]{{1}, {2}}, 0);
        accessTree_9_x[1] = new Node(new int[]{9, 9}, new int[][]{{3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}}, 1);
        accessTree_9_x[2] = new Node(new int[]{2, 2}, new int[][]{{12}, {13}}, 2);
        accessTree_9_x[3] = new Node(new int[]{1, 1}, new int[][]{{14}}, 3);
        accessTree_9_x[4] = new Node(new int[]{1, 1}, new int[][]{{15}}, 4);
        accessTree_9_x[5] = new Node(new int[]{1, 1}, new int[][]{{16}}, 5);
        accessTree_9_x[6] = new Node(new int[]{1, 1}, new int[][]{{17}}, 6);
        accessTree_9_x[7] = new Node(new int[]{1, 1}, new int[][]{{18}}, 7);
        accessTree_9_x[8] = new Node(new int[]{1, 1}, new int[][]{{19}}, 8);
        accessTree_9_x[9] = new Node(new int[]{1, 1}, new int[][]{{20}}, 9);
        accessTree_9_x[10] = new Node(new int[]{1, 1}, new int[][]{{21}}, 10);
        accessTree_9_x[11] = new Node(new int[]{1, 1}, new int[][]{{22}}, 11);
        accessTree_9_x[12] = new Node(new int[]{1, 9}, new int[][]{{23}, {24}, {25}, {26}, {27}, {28}, {29}, {30}, {31}}, 12);
        accessTree_9_x[13] = new Node("S", 1, 13);
        accessTree_9_x[14] = new Node("A", 1, 14);
        accessTree_9_x[15] = new Node("B", 1, 15);
        accessTree_9_x[16] = new Node("C", 1, 16);
        accessTree_9_x[17] = new Node("D", 1, 17);
        accessTree_9_x[18] = new Node("E", 1, 18);
        accessTree_9_x[19] = new Node("F", 1, 19);
        accessTree_9_x[20] = new Node("G", 1, 20);
        accessTree_9_x[21] = new Node("H", 1, 21);
        accessTree_9_x[22] = new Node("I", 1, 22);
        accessTree_9_x[23] = new Node(new int[]{1, 1}, new int[][]{{32}}, 23);
        accessTree_9_x[24] = new Node(new int[]{1, 1}, new int[][]{{33}}, 24);
        accessTree_9_x[25] = new Node(new int[]{1, 1}, new int[][]{{34}}, 25);
        accessTree_9_x[26] = new Node(new int[]{1, 1}, new int[][]{{35}}, 26);
        accessTree_9_x[27] = new Node(new int[]{1, 1}, new int[][]{{36}}, 27);
        accessTree_9_x[28] = new Node(new int[]{1, 1}, new int[][]{{37}}, 28);
        accessTree_9_x[29] = new Node(new int[]{1, 1}, new int[][]{{38}}, 29);
        accessTree_9_x[30] = new Node(new int[]{1, 1}, new int[][]{{39}}, 30);
        accessTree_9_x[31] = new Node(new int[]{1, 1}, new int[][]{{40}}, 31);
        accessTree_9_x[32] = new Node("A", 1, 32);
        accessTree_9_x[33] = new Node("B", 1, 33);
        accessTree_9_x[34] = new Node("C", 1, 34);
        accessTree_9_x[35] = new Node("D", 1, 35);
        accessTree_9_x[36] = new Node("E", 1, 36);
        accessTree_9_x[37] = new Node("F", 1, 37);
        accessTree_9_x[38] = new Node("G", 1, 38);
        accessTree_9_x[39] = new Node("H", 1, 39);
        accessTree_9_x[40] = new Node("I", 1, 40);
        int[] level_9_x = {3,4,5,6,7,8,9,10,11,23,24,25,26,27,28,29,30,31};
        Element[] sus_9_x = new Element[9];
        String[] S0_9_x = {"A", "B", "C", "D", "E", "F", "G", "H", "I"};
        String[][] S_9_x = {{"A"}, {"B"}, {"C"}, {"D"}, {"E"}, {"F"}, {"G"}, {"H"}, {"I"}};

        //--------------------------------------------------------------------------------------------------------------
        //==============================================================================================================
        //--------------------------------------------------------------------------------------------------------------

        Node[][] accessTree_n = {accessTree_0, accessTree_1, accessTree_2, accessTree_3, accessTree_4, accessTree_5,
                accessTree_6, accessTree_7, accessTree_xx, accessTree_3_X, accessTree_5_x, accessTree_7_x, accessTree_9_x};
        int[][] level_n = {level_0, level_1, level_2, level_3, level_4, level_5, level_6, level_7, level_xx, level_3_x,
                level_5_x, level_7_x, level_9_x};
        Element[][] sus_n = {sus_0, sus_1, sus_2, sus_3, sus_4, sus_5, sus_6, sus_7, sus_xx, sus_3_x, sus_5_x, sus_7_x, sus_9_x};
        String[][] S0_n = {S0_0, S0_1, S0_2, S0_3, S0_4, S0_5, S0_6, S0_7, S0_xx, S0_3_x, S0_5_x, S0_7_x, S0_9_x};
        String[][][] S_n = {S_0, S_1, S_2, S_3, S_4, S_5, S_6, S_7, S_xx, S_3_x, S_5_x, S_7_x, S_9_x};
        //0-3 合作节点分别为3，5，7，10，每个合作节点固定两个子节点。
        //4-7 合作节点固定为5，每个节点子节点为3，4，5，6。
        int tree = 12;
        Node[] accessTree = accessTree_n[tree];
        int[] level = level_n[tree];
        Element[] sus = sus_n[tree];
        String[] S0 = S0_n[tree];
        String[][] S = S_n[tree];

        String message = "wangwang";

        setup(pairingFileName, pkFileName, mskFileName);

        long start = System.currentTimeMillis();
        for (int i=0;i<10;i++) {
            encrypt(pairingFileName, message, pkFileName, ctFileName, accessTree, 5, level);
        }
        System.out.println("Encrypt: "+(System.currentTimeMillis()-start)/10);

//        long start_k = System.currentTimeMillis();
//        for (int i=0;i<1;i++){
//            keygen(pairingFileName, mskFileName, skFileName, pkFileName, S0);
//        }
//        System.out.println("KeyGen: "+(System.currentTimeMillis()-start_k)/100);
//
//        long start_d = System.currentTimeMillis();
//        for(int i=0;i<1;i++){
//            decrypt(pairingFileName, S0, ctFileName, skFileName, accessTree, level);
//        }
//        System.out.println("Decrypt: "+(System.currentTimeMillis()-start_d)/100);
//
//        long time=0;
//        for(int i=0;i<1;i++) {
//
//            for(int j=0;j< level.length/2;j++){
//                keygen(pairingFileName, mskFileName, skFileName, pkFileName, S[j]);
//                long time1=System.currentTimeMillis();
//                sus[j]=Semi_decrypt(pairingFileName, skFileName, ctFileName, S[j], accessTree, level[j]);
//                time+=System.currentTimeMillis()-time1;
//            }
//            for(int j= level.length/2;j< level.length;j++){
//                long time2 = System.currentTimeMillis();
//                Add_op(pairingFileName, skFileName, ctFileName, S[j- level.length/2], accessTree, level[j]);
//                time+=System.currentTimeMillis()-time2;
//            }
//
//            long time11 = System.currentTimeMillis();
//            Element share_decrypt_message = ShareDecrypt(pairingFileName, ctFileName, sus);
//            time+=System.currentTimeMillis()-time11;
//        }
//        System.out.println("Collaborative decryption: "+time/100);

    }
}
