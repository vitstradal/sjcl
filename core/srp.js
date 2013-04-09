/** @fileOverview Javascript SRP implementation.
 *
 * This file contains a partial implementation of the SRP (Secure Remote
 * Password) password-authenticated key exchange protocol. Given a user
 * identity, salt, and SRP group, it generates the SRP verifier that may
 * be sent to a remote server to establish and SRP account.
 *
 * For more information, see http://srp.stanford.edu/.
 *
 * @author Quinn Slack
 */

/**
 * Compute the SRP verifier from the username, password, salt, and group.
 * @class SRP
 */
sjcl.keyexchange.srp = function(group_name, hash_name) {
    this.init(group_name, hash_name);
};

  /**
   * Calculates SRP v, the verifier. 
   *   v = g^x mod N [RFC 5054]
   * @param {String} I The username.
   * @param {String} P The password.
   * @param {Object} s A bitArray of the salt.
   * @param {Object} group The SRP group. Use sjcl.keyexchange.srp.knownGroup
                           to obtain this object.
   * @return {Object} A bitArray of SRP v.
   */

sjcl.keyexchange.srp.makeVerifier = function(I, P, s, group) {
    var x;
    x = sjcl.keyexchange.srp.makeX(I, P, s);
    x = sjcl.bn.fromBits(x);
    return group.g.powermod(x, group.N);
};

  /**
   * Calculates SRP x.
   *   x = SHA1(<salt> | SHA(<username> | ":" | <raw password>)) [RFC 2945]
   * @param {String} I The username.
   * @param {String} P The password.
   * @param {Object} s A bitArray of the salt.
   * @return {Object} A bitArray of SRP x.
   */
sjcl.keyexchange.srp.makeX =  function(I, P, s) {
    var inner = sjcl.hash.sha1.hash(I + ':' + P);
    return sjcl.hash.sha1.hash(sjcl.bitArray.concat(s, inner));
};

  /**
   * Returns the known SRP group with the given size (in bits).
   * @param {String} i The size of the known SRP group.
   * @return {Object} An object with "N" and "g" properties.
   */
sjcl.keyexchange.srp.knownGroup = function(group_name) {
    if ( group_name === undefined ) { group_name = 1024; }
    console.log("group name:"+ group_name);
    if (typeof group_name !== "string") { group_name = group_name.toString(); }

    if (!sjcl.keyexchange.srp._didInitKnownGroups) { sjcl.keyexchange.srp._initKnownGroups(); }

    var group = sjcl.keyexchange.srp._knownGroups[group_name];

    //console.log("kGret:" + (group === undefined));
    return  group;
};

  /**
   * Initializes bignum objects for known group parameters.
   * @private
   */
sjcl.keyexchange.srp._didInitKnownGroups =  false;
sjcl.keyexchange.srp._initKnownGroups = function() {
    var i, size, group;
    for (i=0; i < sjcl.keyexchange.srp._knownGroupSizes.length; i++) {
      //console.log("ikg:"+i);
      size = sjcl.keyexchange.srp._knownGroupSizes[i];
      //console.log("ikg:size:"+size);

      group = sjcl.keyexchange.srp._knownGroups[size.toString()];
      group.N = new sjcl.bn(group.N);
      group.g = new sjcl.bn(group.g);
      //console.log("ikg:group:",group);
    }
    sjcl.keyexchange.srp._didInitKnownGroups = true;
};

sjcl.keyexchange.srp._knownGroupSizes = [1024, 1536, 2048];
sjcl.keyexchange.srp._knownGroups = {
    1024: {
      N: "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
         "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
         "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
         "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
         "FD5138FE8376435B9FC61D2FC0EB06E3",
      g:2
    },

    1536: {
      N: "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA961" +
         "4B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F843" +
         "80B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0B" +
         "E3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF5" +
         "6EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734A" +
         "F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E" +
         "8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
      g: 2
    },

    2048: {
      N: "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" +
         "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
         "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" +
         "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" +
         "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" +
         "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
         "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" +
         "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
         "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
         "9E4AFF73",
      g: 2
    },
};

sjcl.keyexchange.srp._hashes = {
        'sha1': sjcl.hash.sha1.hasn,
};

sjcl.keyexchange.srp.prototype = {

  init: function(group_name, hash_name) {
    if( hash_name === null ) { hash_name = 'sha1'; };
    if( group_name === null ) { group_name = 1024; };
    var group = sjcl.keyexchange.srp.knownGroup(group_name);
    this.hash = sjcl.keyexchange.srp._hashes[hash_name] || sjcl.hash.sha1.hash || null;
    this.bn_g = group.g;
    this.bn_N = group.N;
    if( ! this.bn_g ) { 
      console.log("!!!not g");
    }
    if( ! this.bn_N ) { 
      console.log("!!!not N");
    }
    this.N_length = group.N.bitLength()>>3;
    if(group.N.bitLength() & 7 ) {
        alert("init: die:group.N.bitLen is not in rounded to bytes");
    }
    this.predefined_bn_a = undefined;
    this.predefined_bn_b = undefined;
    this.predefined_bn_s = undefined;
  },

  pad_bn: function(bn) {
    if( bn === null ) { return null; };
    return this.pad_ba(bn.toBits());
  },
  pad_ba: function(arr_ba) {
    if( arr_ba === null ) { return null; };
    var arr_len = sjcl.bitArray.bitLength(arr_ba) / 8;
    var len_req = this.N_length;
    //console.log("pad:len*8:", sjcl.bitArray.bitLength(arr_ba) );
    //console.log("pad:len:", arr_len);
    //console.log("pad:rlen:", len_req);
    if( arr_len >= len_req ) {
      return arr_ba;
    }
    var padding = this._zeroes_ba( len_req - arr_len );
    return sjcl.bitArray.concat(padding, arr_ba);
  },

  _zeroes_ba: function(n) {
    var ret = [];
    for(var i = 0; i < n / 4; i++ ) {
      ret.push(0);
    }
    return sjcl.bitArray.clamp(ret, n * 8);
  },

  // val:  num  | string_hex | big_num | bitArray
  // ret: bitArray
  _all_to_ba: function(val) {
    if( val instanceof Array ) {
      // BitArray
      return val;
    }
    // hx string, bigNum, num
    return (new sjcl.bn(s)).toBits();
  },
  _all_to_bn: function(val) {
    if( val instanceof Array ) {
      // BitArray
      return sjcl.bn.fromBits(val);
    }
    // hx string, bigNum, num
    return new sjcl.bn(val);
  },

  // I, P: strings
  // s: num  | string_hex | big_num | bitArray
  client_init: function(s_I, s_P, s, B, A, a) {
    this.ba_I = sjcl.codec.utf8String.toBits(s_I);
    this.ba_P = sjcl.codec.utf8String.toBits(s_P);
    this.ba_s = this._all_to_ba(s);
    this.bn_x = this._compute_bn_x();
    if( A !== null ) { this.bn_A =  new sjcl.bn(A); }
    if( B !== null ) { this.bn_B =  new sjcl.bn(B); }
    if( a !== null ) { this.bn_a =  new sjcl.bn(a); }
  },


  client_compute_M1: function() {
    this.bn_u = this._compute_bn_u();        // u = HASH(PAD(A) | PAD(B))
    this.bn_k = this._compute_bn_k();        // k = HASH(N | PAD(g))
    this.bn_S = this._compute_bn_S_client(); // S = (B - (k * ((g^x)%N) )) ^ (a + (u * x)) % N
    this.ba_K = this._compute_ba_K();        // K = HASH( PAD(S) )
    this.ba_M1 = this._compute_ba_M1();       // M1 = HASH( HASH(N) XOR HASH(PAD(g)) | HASH(I) | s | PAD(A) | PAD(B) | K )
    //return this.ba_M1.toString();
    return sjcl.codec.hex.fromBits(this.ba_M1);
  },

  client_verify_M2: function(hx_M2_req) {

    this.ba_M2 = this._compute_ba_M2(); // M2 = HASH( PAD(A) | M1 | K )
    var hx_M2 = sjcl.codec.hex.fromBits(this.ba_M2);
    return  hx_M2 == hx_M2_req;
  },
  server_verify_M1: function(hx_M1_req) {
    this.bn_u = this._compute_bn_u();        // u = HASH(PAD(A) | PAD(B))
    this.bn_S = this._compute_bn_S_server(); // S = ( (A * ((v^u)%N)) ^ b) % N
    this.ba_K = this._compute_ba_K();        // K = HASH( PAD(S) )
    this.ba_M1 =this._compute_ba_M1();       // M1 = HASH( HASH(N) XOR HASH(PAD(g)) | HASH(I) | s | PAD(A) | PAD(B) | K )
    var hx_M1 = sjcl.codec.hex.fromBits(this.ba_M1);
    return  hx_M1 == hx_M1_req;
    
  },

  // s: bn | ba | hx str
  //ret: bn_v
  compute_verifier: function(s_I, s_P, s) {
    this.client_init(s_I, s_P, s);
    this.bn_v = this._compute_bn_v();
    return this.bn_v;
  },
  compute_verifier_and_salt: function(s_I, s_P, s_len) {
    this.ba_s = this._generate_bn_s(s_len);
    this.client_init(s_I, s_P, this.ba_s);
    this.bn_v = this._compute_bn_v();
    return [this.bn_v, this.ba_s];
  },
  _generate_bn_s: function(s_len) {
    if( this.predefined_bn_s !== undefined ) { 
      return this.predefined_bn_s;
    }
    //FIXME: paranoia !0
    s_len = s_len || 32;
    return sjcl.random.randomWords(s_len / 32, 0);
  },
  // v: ba || bn || hx str
  // s: ba || bn || hx str
  server_init: function(I, v, s, bn_A, bn_B, bn_b) {
    this.ba_I = sjcl.codec.utf8String.toBits(I);
    this.bn_v = this._all_to_bn(v);
    this.ba_s = this._all_to_ba(s);

    if( bn_A !== undefined ) { this.bn_A = new sjcl.bn(bn_A); }
    if( bn_B !== undefined ) { this.bn_B = new sjcl.bn(bn_B); }
    if( bn_b !== undefined ) { this.bn_b = new sjcl.bn(bn_b); }
  }, 

  // ret: bignumber A
  client_compute_A: function(a_len) {
    a_len = a_len || 256;
    this.bn_a = this._generate_bn_a_or_b(a_len, this.predefined_bn_a);    // a = random()  a has min 256 bits, a < N
    this.bn_A = this._compute_bn_A();              // A = g^a % N
    return this.bn_A;
  },

  server_compute_B: function(b_len) {
    this.bn_b = this._generate_bn_a_or_b(b_len, this.predefined_bn_b);    // a = random()  a has min 256 bits, a < N
    this.bn_k = this._compute_bn_k(); // k = HASH(N | PAD(g))
    this.bn_B = this._compute_bn_B(); // B = ( k*v + (g^b % N) ) % N
    return this.bn_B;
  },
    
  server_compute_M2: function () { 
    this.ba_M2 = this._compute_ba_M2(); // M2 = HASH( PAD(A) | M1 | K )
    return sjcl.codec.hex.fromBits(this.ba_M2);
  },
  get_secret_S:  function() {
    return sjcl.codec.hex.fromBits(this.ba_S);
  },
  get_secret_K: function() {
    return sjcl.codec.hex.fromBits(this.ba_K);
  },
  validate_A_or_B: function(AB) {
    if( !this.bn_N ) { 
      return 0;
    }
    var bn_AB = new sjcl.bn(AB);
    var bn_AB_mod_N = bn_AB.mod(this.bn_N);
    if( bn_AB_mod_N.equals(0) ) {
      // AB % N == 0
      return 0;
    }
    return 1;
  },
  _compute_bn_v: function() { 
    if( !this.bn_x || !this.bn_N || !this.bn_g ) { 
      return null;
    }
    // v = g^x % N
    var bn_v =  this.bn_g.powermod(this.bn_x, this.bn_N);
    return bn_v;
  },
  _compute_bn_B: function() { 
    if( !(this.bn_b && this.bn_k &&  this.bn_v && this.bn_N && this.bn_g) ) {
      console.log("compute_bn_B: something is null:" + (this.bn_b?'':'b') + (this.bn_k?'':'k'));
      return null;
    }
    // B = ( k*v   +   (g^b % N) ) % N
    //      <-kv-->    <---gb -->
    var bn_kv =  this.bn_k.mul(this.bn_v);
    var bn_gb = this.bn_g.copy().powermod(this.bn_b, this.bn_N);
    return bn_kv.add(bn_gb).mod(this.bn_N);
  },
  _compute_bn_x: function () {
    // x = HASH(s | HASH(I | ":" | P))
    //          <--- tmp ---------->
    var ba_dd = sjcl.codec.utf8String.toBits(':');
    if( !this.ba_s  || !this.ba_I || !this.ba_P ) {
      return null;
    }
    var ba_tmp =
        sjcl.bitArray.concat(this.ba_s,
          this.hash(
            sjcl.bitArray.concat(this.ba_I,
              sjcl.bitArray.concat(ba_dd, this.ba_P))));

    
    var ba_tmp_h = this.hash(ba_tmp);
    //console.log("c_x:ba:", sjcl.codec.hex.fromBits(ba_tmp_h));
    return sjcl.bn.fromBits(ba_tmp_h);
  },
  _generate_bn_a_or_b: function(ab_len, bn_ab){
        if( ! ab_len ) { ab_len = 256; };
        if( bn_ab !== undefined ) { 
          return bn_ab;
        }
        //FIXME: 
        //var ba_a = sjcl.random.randomWords(a_len / 32, 6);
        var ba_ab = sjcl.random.randomWords(ab_len / 32, 0);
        return sjcl.bn.fromBits(ba_ab);
  },
  _compute_bn_A: function(){
    if( !this.bn_g || !this.bn_N ){ 
      console.log("compute_bn_A: skip");
      return null;
    }
    // A = g^a % N
    var bn_A = this.bn_g.copy().powermod( this.bn_a, this.bn_N);
    return  bn_A;
  },
  _compute_bn_u: function(){
    // u = HASH(PAD(A) | PAD(B))
    if( !this.bn_A || !this.bn_B ){
      return null;
    }
    var A_pad = this.bn_A.toBits();
    var B_pad = this.bn_B.toBits();
    var AB = sjcl.bitArray.concat(A_pad, B_pad);
    return this._hash_and_bn(AB);
  },
  _hash_and_bn: function(ba) {
    if( !ba ) { 
      return null;
    }
    return sjcl.bn.fromBits(this.hash(ba));
  },
  _compute_bn_k: function(){
    // k = HASH(N | PAD(g))
    //          <--tmp-->
    if( !this.bn_g || !this.bn_N) {
      console.log('compute_k: something is null');
      return null;
    }
    var g_pad = this.pad_bn(this.bn_g);
    //console.log("g:" + this.bn_g);
    //console.log("g_pad:", sjcl.codec.hex.fromBits(g_pad));

    var ba_N = this.bn_N.toBits();
    var ba_tmp = sjcl.bitArray.concat(ba_N, g_pad);
    return  this._hash_and_bn(ba_tmp);
  },
  _compute_bn_S_server: function(){
    // S = ( (A * ((v^u)%N)) ^ b) % N
    //        <--tmp1-----> 
    var A = this.bn_A;
    var v = this.bn_v;
    var u = this.bn_u;
    var N = this.bn_N;
    var b = this.bn_b;
    if( ! (A && v && u && N && b ) ) {
      console.log("compute_S_server:neco je null");
      return null;
    }
    var tmp1 = v.powermod(u, N).mul(A);
    return tmp1.powermod(b,N);
  },
  _compute_bn_S_client: function(){
    // S = (B - (k * ((g^x)%N) )) ^ (a + (u * x)) % N
    //           <--  tmp1  -->   <--- tmp2 ---->
    var g = this.bn_g;
    var N = this.bn_N;
    var x = this.bn_x;
    var k = this.bn_k;
    var a = this.bn_a;
    var u = this.bn_u;
    var B = this.bn_B;
    if( ! (g && N && x && k && a && u && B )) { 
      console.log('compute_S_cl: something is null');
      return null
    }

    var bn_tmp1 = g.powermod(x, N).mul(k);
    var bn_tmp2 = u.mul(x).add(a);
    var ret = B.sub(bn_tmp1).powermod(bn_tmp2, N);
    return ret;
  },
  _compute_ba_M1: function(){
    // M1 = HASH( (HASH(N) XOR HASH(PAD(g))) | HASH(I) | s | PAD(A) | PAD(B) | K )
    //             <--   ng        -->     
    //             <------------------- tmp1 ---------------------------------->
    var ba_Nh = this.hash(this.bn_N.toBits());

    console.log("baNh:",  this._ba2hx(ba_Nh));

    var ba_gph= this.hash(this.pad_bn(this.bn_g));
    var ba_Ih = this.hash(this.ba_I);
    var ba_s  = this.ba_s;
    var ba_Ap = this.pad_bn(this.bn_A);
    var ba_Bp = this.pad_bn(this.bn_B);
    var ba_K  = this.ba_K;

    console.log("bagph:",  this._ba2hx(ba_gph));

    if( !( ba_Nh && ba_gph && ba_s && ba_Ap && ba_K && ba_Ih )){ 
      return null;
    }
    var ba_ng = this._xor_ba(ba_Nh, ba_gph);
    console.log("ng:",  this._ba2hx(ba_ng));

    var ba_tmp1 =
        sjcl.bitArray.concat(ba_ng,
          sjcl.bitArray.concat(ba_Ih,
            sjcl.bitArray.concat(ba_s,
              sjcl.bitArray.concat(ba_Ap,
                sjcl.bitArray.concat(ba_Bp,ba_K)))));

    console.log("bf h:",  this._ba2hx(ba_tmp1));
    console.log("bf h:",  this._ba2hx(this.hash(ba_tmp1)));
    return this.hash(ba_tmp1);
  },
  _compute_ba_K: function() {
    // K = HASH( PAD(S) )
    if( !this.bn_S ) {
      return null;
    }
    var ba_Sp = this.pad_bn(this.bn_S);
    return this.hash(ba_Sp);
  },
  _compute_ba_M2: function(){
    // M2 = HASH( PAD(A) | M1 | K )
    var ba_K = this.ba_K;
    var ba_M1 = this.ba_M1;
    var ba_Ap = this.pad_bn(this.bn_A);

    if( ! (ba_K && ba_M1 && ba_Ap )) { 
      return null;
    }
    var ba_tmp1 =
        sjcl.bitArray.concat(ba_Ap,
          sjcl.bitArray.concat(ba_M1, ba_K));
    return this.hash(ba_tmp1);
  },
  // a1 ^= a2;
  _xor_ba: function(a1, a2){
    var len1 = sjcl.bitArray.bitLength(a1);
    var len2 = sjcl.bitArray.bitLength(a2);
    if(  len1 != len2 ) {
      //die
      console.log("xor: lenghts differ", len1, len2);
      return null;
    }
    var i;
    //console.log("xor len:", a1.length);
    for(i = 0; i < a1.length - 1 ; i++) {
      //console.log("xoring:", i);
      a1[i] ^= a2[i];
    }
    //console.log("last:", i);
    a1[i] ^= a2[i] & 0xffffffff;
    return a1;

  },
  _ba2hx: function(ba) {
    return sjcl.codec.hex.fromBits(ba);
  },
};


// usage:
// user inputs: I P
// client: srp = new srp('1024', 'sha512');
// client: A = srp.compute_A_hx(I, P);
// client: a = srp.bn_a
// clinet: //send_to_server1(I,A);
//
// -- client: srp = new srp('1024', 'sha512');
// -- client: srp.init_client(I,P,A,a);
//
// client: M1 = srp.compute_M1_hx(B);
// clinet: //send_to_server2(M1);
//
// client: is_ok = srp.check_M2(M2_hx);
// client: K = srp.K;

