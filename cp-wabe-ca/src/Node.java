import it.unisa.dia.gas.jpbc.Element;

import java.util.Arrays;

public class Node {

    public int[] gate;

    public int[][] children;

    public String att;

    public Element secretShare;

    public int weight;

    public boolean valid;

    public int index;

    public Node(int[] gate, int[][] children, int index){
        this.gate = gate;
        this.children = children;
        this.weight = 1;
        this.index = index;
    }

    public Node(String att, int weight, int index){
        this.att = att;
        this.weight = weight;
        this.index = index;
    }

    public boolean isLeaf(){
        return this.children == null;
    }

    public String toString(){
        if (this.isLeaf()){
            return this.att;
        }
        else {
            return Arrays.toString(this.gate);
        }
    }

}
