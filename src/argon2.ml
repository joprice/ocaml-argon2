open Ctypes

module Kind = struct
  type t = C.Function.Kind.t = D | I | ID

  let argon2_type2string = C.Function.argon2_type2string
  (*
    foreign "argon2_type2string"
      (t (* type *) @-> int (* uppercase *) @-> returning string)
      *)

  let show (case : [ `Upper | `Lower ]) t =
    let case = match case with `Upper -> 1 | `Lower -> 0 in
    argon2_type2string t case
end

type kind = Kind.t = D | I | ID

let show_kind = Kind.show

type version = C.Function.Version.t = VERSION_10 | VERSION_13 | VERSION_NUMBER

module ErrorCodes = struct
  type t = C.Function.ErrorCodes.t =
    | OK
    | OUTPUT_PTR_NULL
    | OUTPUT_TOO_SHORT
    | OUTPUT_TOO_LONG
    | PWD_TOO_SHORT
    | PWD_TOO_LONG
    | SALT_TOO_SHORT
    | SALT_TOO_LONG
    | AD_TOO_SHORT
    | AD_TOO_LONG
    | SECRET_TOO_SHORT
    | SECRET_TOO_LONG
    | TIME_TOO_SMALL
    | TIME_TOO_LARGE
    | MEMORY_TOO_LITTLE
    | MEMORY_TOO_MUCH
    | LANES_TOO_FEW
    | LANES_TOO_MANY
    | PWD_PTR_MISMATCH
    | SALT_PTR_MISMATCH
    | SECRET_PTR_MISMATCH
    | AD_PTR_MISMATCH
    | MEMORY_ALLOCATION_ERROR
    | FREE_MEMORY_CBK_NULL
    | ALLOCATE_MEMORY_CBK_NULL
    | INCORRECT_PARAMETER
    | INCORRECT_TYPE
    | OUT_PTR_MISMATCH
    | THREADS_TOO_FEW
    | THREADS_TOO_MANY
    | MISSING_ARGS
    | ENCODING_FAIL
    | DECODING_FAIL
    | THREAD_FAIL
    | DECODING_LENGTH_FAIL
    | VERIFY_MISMATCH
    | Other of int

  let message error_code = C.Function.ErrorCodes.argon2_error_message error_code
end

let argon2i_hash_encoded = C.Function.argon2i_hash_encoded
let argon2i_hash_raw = C.Function.argon2i_hash_raw
let argon2d_hash_encoded = C.Function.argon2d_hash_encoded
let argon2d_hash_raw = C.Function.argon2d_hash_raw
let argon2id_hash_encoded = C.Function.argon2id_hash_encoded
let argon2id_hash_raw = C.Function.argon2id_hash_raw
let argon2_hash = C.Function.argon2_hash
let argon2i_verify = C.Function.argon2i_verify
let argon2d_verify = C.Function.argon2d_verify
let argon2id_verify = C.Function.argon2id_verify
let argon2_verify = C.Function.argon2_verify
let argon2_encodedlen = C.Function.argon2_encodedlen

let hash_encoded hash_fun ~t_cost ~m_cost ~parallelism ~pwd ~salt ~hash_len
    ~encoded_len =
  let u_t_cost = Unsigned.UInt32.of_int t_cost in
  let u_m_cost = Unsigned.UInt32.of_int m_cost in
  let u_parallelism = Unsigned.UInt32.of_int parallelism in

  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  let s_salt_len = Unsigned.Size_t.of_int @@ String.length salt in

  let s_hash_len = Unsigned.Size_t.of_int hash_len in

  let encoded = allocate_n char ~count:encoded_len in
  let s_encoded_len = Unsigned.Size_t.of_int encoded_len in

  match
    hash_fun u_t_cost u_m_cost u_parallelism pwd s_pwd_len salt s_salt_len
      s_hash_len encoded s_encoded_len
  with
  | C.Function.ErrorCodes.OK ->
      let encoded = string_from_ptr encoded ~length:(encoded_len - 1) in
      Result.Ok encoded
  | e -> Result.Error e

let hash_raw hash_fun ~t_cost ~m_cost ~parallelism ~pwd ~salt ~hash_len =
  let u_t_cost = Unsigned.UInt32.of_int t_cost in
  let u_m_cost = Unsigned.UInt32.of_int m_cost in
  let u_parallelism = Unsigned.UInt32.of_int parallelism in

  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  let s_salt_len = Unsigned.Size_t.of_int @@ String.length salt in

  let hash = allocate_n char ~count:hash_len |> to_voidp in
  let s_hash_len = Unsigned.Size_t.of_int hash_len in

  match
    hash_fun u_t_cost u_m_cost u_parallelism pwd s_pwd_len salt s_salt_len hash
      s_hash_len
  with
  | C.Function.ErrorCodes.OK ->
      let hash = string_from_ptr (from_voidp char hash) ~length:hash_len in
      Result.Ok hash
  | e -> Result.Error e

let verify verify_fun ~encoded ~pwd =
  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  match verify_fun encoded pwd s_pwd_len with
  | C.Function.ErrorCodes.OK -> Result.Ok true
  | e -> Result.Error e

module type HashBindings = sig
  val hash_raw :
    Unsigned.uint32 ->
    Unsigned.uint32 ->
    Unsigned.uint32 ->
    string ->
    Unsigned.size_t ->
    string ->
    Unsigned.size_t ->
    unit Ctypes_static.ptr ->
    Unsigned.size_t ->
    ErrorCodes.t

  val hash_encoded :
    Unsigned.uint32 ->
    Unsigned.uint32 ->
    Unsigned.uint32 ->
    string ->
    Unsigned.size_t ->
    string ->
    Unsigned.size_t ->
    Unsigned.size_t ->
    char Ctypes_static.ptr ->
    Unsigned.size_t ->
    ErrorCodes.t

  val verify : string -> string -> Unsigned.size_t -> ErrorCodes.t
end

module type HashFunctions = sig
  type hash
  type encoded

  val hash_raw :
    t_cost:int ->
    m_cost:int ->
    parallelism:int ->
    pwd:string ->
    salt:string ->
    hash_len:int ->
    (hash, ErrorCodes.t) result

  val hash_encoded :
    t_cost:int ->
    m_cost:int ->
    parallelism:int ->
    pwd:string ->
    salt:string ->
    hash_len:int ->
    encoded_len:int ->
    (encoded, ErrorCodes.t) result

  val verify : encoded:encoded -> pwd:string -> (bool, ErrorCodes.t) result
  val hash_to_string : hash -> string
  val encoded_to_string : encoded -> string
end

module MakeInternal (H : HashBindings) : HashFunctions = struct
  type hash = string
  type encoded = string

  let hash_to_string h = h
  let encoded_to_string e = e
  let hash_raw = hash_raw H.hash_raw
  let hash_encoded = hash_encoded H.hash_encoded
  let verify = verify H.verify
end

module I = MakeInternal (struct
  let hash_raw = argon2i_hash_raw
  let hash_encoded = argon2i_hash_encoded
  let verify = argon2i_verify
end)

module D = MakeInternal (struct
  let hash_raw = argon2d_hash_raw
  let hash_encoded = argon2d_hash_encoded
  let verify = argon2d_verify
end)

module ID = MakeInternal (struct
  let hash_raw = argon2id_hash_raw
  let hash_encoded = argon2id_hash_encoded
  let verify = argon2id_verify
end)

type hash = string
type encoded = string

let hash ~t_cost ~m_cost ~parallelism ~pwd ~salt ~kind ~hash_len ~encoded_len
    ~version =
  let u_t_cost = Unsigned.UInt32.of_int t_cost in
  let u_m_cost = Unsigned.UInt32.of_int m_cost in
  let u_parallelism = Unsigned.UInt32.of_int parallelism in

  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  let s_salt_len = Unsigned.Size_t.of_int @@ String.length salt in

  let hash = allocate_n char ~count:hash_len |> to_voidp in
  let s_hash_len = Unsigned.Size_t.of_int hash_len in

  let encoded = allocate_n char ~count:encoded_len in
  let s_encoded_len = Unsigned.Size_t.of_int encoded_len in

  let res =
    argon2_hash u_t_cost u_m_cost u_parallelism pwd s_pwd_len salt s_salt_len
      hash s_hash_len encoded s_encoded_len kind version
  in
  match res with
  | C.Function.ErrorCodes.OK ->
      let hash = string_from_ptr (from_voidp char hash) ~length:hash_len in
      let encoded = string_from_ptr encoded ~length:(encoded_len - 1) in
      Result.Ok (hash, encoded)
  | _ as e -> Result.Error e

let verify ~encoded ~pwd ~kind =
  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  match argon2_verify encoded pwd s_pwd_len kind with
  | C.Function.ErrorCodes.OK -> Result.Ok true
  | e -> Result.Error e

let encoded_len ~t_cost ~m_cost ~parallelism ~salt_len ~hash_len ~kind =
  let u_t_cost = Unsigned.UInt32.of_int t_cost in
  let u_m_cost = Unsigned.UInt32.of_int m_cost in
  let u_parallelism = Unsigned.UInt32.of_int parallelism in
  let u_salt_len = Unsigned.UInt32.of_int salt_len in
  let u_hash_len = Unsigned.UInt32.of_int hash_len in
  let len =
    argon2_encodedlen u_t_cost u_m_cost u_parallelism u_salt_len u_hash_len kind
  in
  Unsigned.Size_t.to_int len
