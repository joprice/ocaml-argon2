(*open Ctypes*)

module Types (F : Ctypes.TYPE) = struct
  (*open F*)
  module ErrorCodes = struct
    type t =
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
  end
end
