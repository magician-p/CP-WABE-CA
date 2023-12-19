import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AccessTree {

    public static Element[] randomP(int d, Element s, Pairing bp){

        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i=1;i<d;i++){
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return coef;
    }

    public static Element qx(Element index, Element[] coef, Pairing bp){

        Element res = coef[0].getImmutable();
        for(int i=1;i<coef.length;i++){
            Element exp = bp.getZr().newElement(i).getImmutable();
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
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

    public static void nodeShare(Node[] nodes, Node n, Pairing bp){

        if(!n.isLeaf()){
            Element[] coef = randomP(n.gate[0], n.secretShare, bp);
            for(int i=0;i<n.children.length;i++){
                Node childNode = nodes[n.children[i][0]];
                int weight = childNode.weight;
                for(int j=0;j<weight;j++){
                    childNode = nodes[n.children[i][j]];
                    childNode.secretShare = qx(bp.getZr().newElement(n.children[i][j]), coef, bp);
                    nodeShare(nodes, childNode, bp);
                }
            }
        }
    }

    public static boolean nodeRecover(Node[] nodes, Node n, String[] atts, Pairing bp){

        if(!n.isLeaf()){
            List<Integer> validChildrenList = new ArrayList<>();
            int[] validChildren;
            for(int i=0;i<n.children.length;i++){
                Node childNode = nodes[n.children[i][0]];
                if(nodeRecover(nodes, childNode, atts, bp)){
                    for(int j=0;j<childNode.weight;j++){
                        validChildrenList.add(n.children[i][j]);
                    }
                    if(validChildrenList.size() == n.gate[0]){
                        n.valid = true;
                        break;
                    }
                }
            }
            if(validChildrenList.size() == n.gate[0]){
                validChildren = validChildrenList.stream().mapToInt(i->i).toArray();
                Element secret = bp.getGT().newOneElement().getImmutable();
                //Element secret = bp.getZr().newZeroElement().getImmutable();
                for(int i:validChildren){
                    Element delta = lagrange(i, validChildren, 0, bp);
                    secret = secret.mul(nodes[i].secretShare.duplicate().powZn(delta));
                    //secret = secret.add(nodes[i].secretShare.duplicate().mul(delta));
                }
                n.secretShare = secret;
                //System.out.println(n.secretShare.isEqual(bp.getZr().newElement(99)));
            }
        }
        else {
            if (Arrays.asList(atts).contains(n.att)){
                n.valid = true;
            }
        }
        return n.valid;
    }

//    public static void main(String[] args){
//        Pairing bp = PairingFactory.getPairing("a.properties");
//
//        Node[] accessTree = new Node[10];
//        accessTree[0] = new Node(new int[]{5, 5}, new int[][]{{1}, {2}, {3}, {4}, {5}, {6,7,8,9}}, 0);
//        accessTree[1] = new Node("A", 1, 1);
//        accessTree[2] = new Node("B", 1, 2);
//        accessTree[3] = new Node("C", 1, 3);
//        accessTree[4] = new Node("D", 1, 4);
//        accessTree[5] = new Node("E", 1, 5);
//        accessTree[6] = new Node("S", 4, 6);
//        accessTree[7] = new Node("S", 4, 7);
//        accessTree[8] = new Node("S", 4, 8);
//        accessTree[9] = new Node("S", 4, 9);
//        int[] level = {1,2,3,4,5};
//        Su[] sus = new Su[5];
//
//        accessTree[0].secretShare=bp.getZr().newElement(99).getImmutable();
//        nodeShare(accessTree, accessTree[0], bp);
//        String[] atts = {"A", "B", "C", "D", "E"};
//        nodeRecover(accessTree, accessTree[0], atts, bp);
//    }
}
