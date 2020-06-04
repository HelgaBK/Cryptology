public class SHA1 {
    int[] SHA1Constant={
            0x5a827999, 
            0x6ed9eba1, 
            0x8f1bbcdc, 
            0xca62c1d6};
    int[] HashVal;

    public static void main(String[] args) {
        SHA1 SH = new SHA1();

        String X = "";
        for(int i=0;i<1000000;i++){
            X+="a";
        }
        System.out.println(X.length());
        SH.SHA1Digest(SH.ParsingMessage(SH.PaddingMessage(X.getBytes(),X.length()*8)));
    }
    public byte[] PaddingMessage(byte[] M,long l){
        long k = (447-l % 512 + 512) % 512;
        byte[] PaddedMessage = new byte[(int)l/8+((int)k+1)/8+8];
        int Size = (int)l/8;
        System.arraycopy(M, 0, PaddedMessage, 0, ((int)l/8));
        for(int i=0;i<(k+1)/8;i++){
            if (i==0){
                PaddedMessage[Size] = (byte)128;
            }
            else PaddedMessage[Size] = 0;
            Size++;
        }
        PaddedMessage[Size]=0;
        PaddedMessage[Size+1]=0;
        PaddedMessage[Size+2]=0;
        PaddedMessage[Size+3]=0;
        
        PaddedMessage[Size+4]=(byte)((int)l>>24);
        PaddedMessage[Size+5]=(byte)(((int)l<<8)>>24);
        PaddedMessage[Size+6]=(byte)(((int)l<<16)>>24);
        PaddedMessage[Size+7]=(byte)(((int)l<<24)>>24);
        return PaddedMessage;
    }
    public int[] ParsingMessage(byte[] M){
        int[] ParsedMessage = new int[M.length/4];
        int idx=0;
        for(int i=0;i<M.length;i+=4){
            int[] ins = new int[4];
            for(int j=0;j<4;j++){
                ins[j] = M[i+j];
                if (ins[j]<0) ins[j]+=256;
            }
            ParsedMessage[idx] =  ins[0];
            ParsedMessage[idx] = (ParsedMessage[idx]<<8)| ins[1];
            ParsedMessage[idx] = (ParsedMessage[idx]<<8)| ins[2];
            ParsedMessage[idx] = (ParsedMessage[idx]<<8)| (ins[3]);
            idx++;
        }
        return ParsedMessage;
    }
    public int SHA1F(int t,int x,int y,int z){
        if (t/20 == 0){
            return (x&y) ^ (~x&z);
        }
        else if (t/20 == 1) return (x ^ y ^ z);
        else if (t/20 == 2) return (x&y) ^ (x&z) ^ (y&z);
        else return (x ^ y ^ z);
    }
    public int[] SHA1Digest(int[] M){
        int[] Hash= {0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
        int N = M.length/16;
        for(int i=1;i<=N;i++){
            int[] MSched = new int[80];
            for(int t=0;t<80;t++){
                if (t<16) MSched[t] = M[(i-1)*16+t];
                else MSched[t] = Integer.rotateLeft(MSched[t-3]^MSched[t-8]^MSched[t-14]^MSched[t-16],1);
            }
            int a = Hash[0];
            int b = Hash[1];
            int c = Hash[2];
            int d = Hash[3];
            int e = Hash[4];
            
            for(int t=0;t<80;t++){
                int T = Integer.rotateLeft(a, 5) + SHA1F(t,b,c,d) + e + SHA1Constant[t/20] + MSched[t];
                e = d;
                d = c;
                c = Integer.rotateLeft(b, 30);
                b = a;
                a = T;
            }
            Hash[0] = a + Hash[0];
            Hash[1] = b + Hash[1];
            Hash[2] = c + Hash[2];
            Hash[3] = d + Hash[3];
            Hash[4] = e + Hash[4];
        }
        System.out.println(Integer.toHexString(Hash[0])+" "+Integer.toHexString(Hash[1])+" "+Integer.toHexString(Hash[2])+" "+Integer.toHexString(Hash[3])+" "+Integer.toHexString(Hash[4]));
        return Hash;
    }
}