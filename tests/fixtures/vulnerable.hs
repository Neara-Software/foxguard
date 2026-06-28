module Vulnerable where

import Foreign.Ptr (Ptr)

foreign import ccall "danger" c_danger :: Ptr a -> IO ()

firstItem :: [Int] -> Int
firstItem xs = head xs
