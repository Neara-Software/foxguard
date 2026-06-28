module Safe where

firstItem :: [Int] -> Maybe Int
firstItem [] = Nothing
firstItem (x : _) = Just x
