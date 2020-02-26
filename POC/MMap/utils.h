#include <sstream>
#include <iomanip>
template< typename T >
std::string int_to_hex(T i)
{
    // Ensure this function is called with a template parameter that makes sense. Note: static_assert is only available in C++11 and higher.
    static_assert(std::is_integral<T>::value, "Template argument 'T' must be a fundamental integer type (e.g. int, short, etc..).");

    std::stringstream stream;
    stream << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex;

    // If T is an 8-bit integer type (e.g. uint8_t or int8_t) it will be 
    // treated as an ASCII code, giving the wrong result. So we use C++17's
    // "if constexpr" to have the compiler decides at compile-time if it's 
    // converting an 8-bit int or not.
    if constexpr (std::is_same_v<std::uint8_t, T>)
    {
        // Unsigned 8-bit unsigned int type. Cast to int (thanks Lincoln) to 
        // avoid ASCII code interpretation of the int. The number of hex digits 
        // in the  returned string will still be two, which is correct for 8 bits, 
        // because of the 'sizeof(T)' above.
        stream << static_cast<int>(i);
    }
    else if (std::is_same_v<std::int8_t, T>)
    {
        // For 8-bit signed int, same as above, except we must first cast to unsigned 
        // int, because values above 127d (0x7f) in the int will cause further issues.
        // if we cast directly to int.
        stream << static_cast<int>(static_cast<uint8_t>(i));
    }
    else
    {
        // No cast needed for ints wider than 8 bits.
        stream << i;
    }

    return stream.str();
}