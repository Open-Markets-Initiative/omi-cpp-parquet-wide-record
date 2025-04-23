#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <utility>

#include "pcap.h"
#include "netinet/if_ether.h"
#include "netinet/ip.h"
#include "netinet/udp.h"
#include "arrow/io/file.h"
#include "parquet/exception.h"
#include "parquet/stream_reader.h"
#include "parquet/stream_writer.h"

namespace nasdaq::itch {

///////////////////////////////////////////////////////////////////////
// pcap types
///////////////////////////////////////////////////////////////////////

// pcap frame index
struct pcap_index {

    static constexpr auto name = "pcap_index";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;

    pcap_index() = default;

    void set(const std::uint64_t value) {
        data = value;
    }

    void increment() {
        data++;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::uint64_t data;
};

inline auto& operator<<(std::ostream& stream, const pcap_index& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const pcap_index& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, pcap_index& field) {
    return stream >> field.data;
}

// pcap timestamp
struct pcap_timestamp {

    static constexpr auto name = "timestamp";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::TIMESTAMP_MICROS;

    pcap_timestamp() = default;

    void set(const std::chrono::microseconds value) {
        data = value;
    }

    void set(const pcap_pkthdr *pkthdr) {
        const auto duration = std::chrono::seconds{pkthdr->ts.tv_sec} + std::chrono::microseconds{pkthdr->ts.tv_usec};
        data = duration_cast<std::chrono::microseconds>(duration);
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::chrono::microseconds data;
};

inline auto& operator<<(std::ostream& stream, const pcap_timestamp& field) {
    const auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(field.data).count();
    return stream << std::put_time(std::gmtime(&timestamp), "%Y-%m-%d %X");
}

inline auto& operator<<(parquet::StreamWriter& stream, const pcap_timestamp& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, pcap_timestamp& field) {
    std::chrono::microseconds microseconds;
    stream >> microseconds;
    field.set(microseconds);

    return stream;
}

///////////////////////////////////////////////////////////////////////
// itch header types
///////////////////////////////////////////////////////////////////////

// Identity of the multicast session
struct session {

    static constexpr auto name = "session";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 10;

    session() = default;

    void set(u_char** current) {
        data.assign(reinterpret_cast<char *>(*current), size);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::string data;
};

inline auto& operator<<(std::ostream& stream, const session& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const session& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, session& field) {
    return stream >> field.data;
}

// message sequence
struct message_sequence {

    static constexpr auto name = "message_sequence";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    message_sequence() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void increment() {
        data++;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::uint64_t data;
};

inline auto& operator<<(std::ostream& stream, const message_sequence& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const message_sequence& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, message_sequence& field) {
    return stream >> field.data;
}

// message index (count)
struct message_index {

    static constexpr auto name = "message_index";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_16;
    static constexpr std::uint32_t size = 2;

    message_index() = default;

    void set(u_char** current) {
        count = htobe16(*reinterpret_cast<uint16_t*>(*current));
        data = 0;
        *current += size;
    }

    bool increment() {
        data++;
        return data <= count;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::uint16_t count = 0;
    std::uint16_t data = 0;
};

inline auto& operator<<(std::ostream& stream, const message_index& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const message_index& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, message_index& field) {
    return stream >> field.data;
}

// message length
struct message_length {

    static constexpr auto name = "message_length";
    static constexpr std::uint32_t size = 2;

    message_length() = default;

    void set(u_char** current, u_char** message) {
        data = htobe16(*reinterpret_cast<std::uint16_t*>(*current));
        *current += size;
        *message = *current;
        *current += data;
    }

    std::uint16_t data;
};

// message type
struct message_type {

    static constexpr auto name = "message_type";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    message_type() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    char data;
};

inline auto& operator<<(std::ostream& stream, const message_type& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const message_type& field) {
    return stream << static_cast<uint8_t>(field.data);
}

inline auto& operator>>(parquet::StreamReader& stream, message_type& field) {
    uint8_t data = 0;
    stream >> data;
    field.data = static_cast<char>(data);
    return stream;
}

///////////////////////////////////////////////////////////////////////
// itch message types
///////////////////////////////////////////////////////////////////////

// NASDAQ market participant identifier associated with the entered order.
struct attribution {

    static constexpr auto name = "attribution";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 4;

    attribution() = default;

    void reset() {
        data.reset();
    }

    void set(u_char** current) {
        std::uint32_t index = 0;
        for (; index < size; ++index) {
            if (*(*current + index) == ' ') { break; }
        }
        data = std::string_view(reinterpret_cast<char *>(*current), index);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::string> data;
};

inline auto& operator<<(std::ostream& stream, const attribution& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const attribution& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, attribution& field) {
    return stream >> field.data;
}

// Indicates the number of the extensions to the Reopening Auction
struct auction_collar_extension {

    static constexpr auto name = "auction_collar_extension";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    auction_collar_extension() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const auction_collar_extension& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const auction_collar_extension& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, auction_collar_extension& field) {
    return stream >> field.data;
}

// Reference price used to set the Auction Collars
struct auction_collar_reference_price {

    static constexpr auto name = "auction_collar_reference_price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    auction_collar_reference_price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const auction_collar_reference_price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const auction_collar_reference_price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, auction_collar_reference_price& field) {
    return stream >> field.data;
}

// Denotes if an issue or quoting participant record is set-up in NASDAQ systems in a live/production, test, or demo state. Please note that firms should only show live issues and quoting participants on public quotation displays.
struct authenticity {

    static constexpr auto name = "authenticity";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    authenticity() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const authenticity& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const authenticity& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, authenticity& field) {
    return stream >> field.data;
}

// Denotes the MWCB Level that was breached.
struct breached_level {

    static constexpr auto name = "breached_level";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    breached_level() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const breached_level& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const breached_level& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, breached_level& field) {
    return stream >> field.data;
}

// The type of order being added.
struct buy_sell_indicator {

    static constexpr auto name = "buy_sell_indicator";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    buy_sell_indicator() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const buy_sell_indicator& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const buy_sell_indicator& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, buy_sell_indicator& field) {
    return stream >> field.data;
}

// The number of shares being removed from the display size of the order as the result of a cancellation.
struct canceled_shares {

    static constexpr auto name = "canceled_shares";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    canceled_shares() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const canceled_shares& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const canceled_shares& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, canceled_shares& field) {
    return stream >> field.data;
}

// The price at which the cross occurred.  Refer to Data Types for field processing notes.
struct cross_price {

    static constexpr auto name = "cross_price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    cross_price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const cross_price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const cross_price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, cross_price& field) {
    return stream >> field.data;
}

// The number of shares matched in the
struct cross_shares {

    static constexpr auto name = "cross_shares";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    cross_shares() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const cross_shares& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const cross_shares& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, cross_shares& field) {
    return stream >> field.data;
}

// The NASDAQ cross session for which the message is being generated.
struct cross_type {

    static constexpr auto name = "cross_type";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    cross_type() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const cross_type& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const cross_type& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, cross_type& field) {
    return stream >> field.data;
}

// The price at which the NOII shares are being calculated.   Refer to Data Types for field processing notes.
struct current_reference_price {

    static constexpr auto name = "current_reference_price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    current_reference_price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const current_reference_price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const current_reference_price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, current_reference_price& field) {
    return stream >> field.data;
}

// Indicates whether the security is an exchange traded product (ETP):
struct etp_flag {

    static constexpr auto name = "etp_flag";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    etp_flag() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const etp_flag& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const etp_flag& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, etp_flag& field) {
    return stream >> field.data;
}

// Tracks the integral relationship of the ETP to the underlying index.   Example: If the underlying Index increases by a value of 1 and the ETP’s Leverage factor is 3, indicates the ETF will increase/decrease (see Inverse) by 3. Note: Leverage Factor of 1 indicates the ETP is NOT leveraged. This field is used for LULD Tier I price band calculation purposes.
struct etp_leverage_factor {

    static constexpr auto name = "etp_leverage_factor";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    etp_leverage_factor() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const etp_leverage_factor& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const etp_leverage_factor& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, etp_leverage_factor& field) {
    return stream >> field.data;
}

// System Event Codes
struct event_code {

    static constexpr auto name = "event_code";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    event_code() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const event_code& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const event_code& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, event_code& field) {
    return stream >> field.data;
}

// The number of shares executed.
struct executed_shares {

    static constexpr auto name = "executed_shares";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    executed_shares() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const executed_shares& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const executed_shares& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, executed_shares& field) {
    return stream >> field.data;
}

// The price at which the order execution occurred. Refer to Data Types for field processing notes.
struct execution_price {

    static constexpr auto name = "execution_price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    execution_price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const execution_price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const execution_price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, execution_price& field) {
    return stream >> field.data;
}

// A hypothetical auction-clearing price for cross orders only. Refer to Data Types for field processing notes.
struct far_price {

    static constexpr auto name = "far_price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    far_price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const far_price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const far_price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, far_price& field) {
    return stream >> field.data;
}

// For NASDAQ-listed issues, this field indicates when a firm is not in compliance with NASDAQ continued listing requirements.
struct financial_status_indicator {

    static constexpr auto name = "financial_status_indicator";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    financial_status_indicator() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const financial_status_indicator& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const financial_status_indicator& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, financial_status_indicator& field) {
    return stream >> field.data;
}

// The market side of the order imbalance.
struct imbalance_direction {

    static constexpr auto name = "imbalance_direction";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    imbalance_direction() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const imbalance_direction& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const imbalance_direction& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, imbalance_direction& field) {
    return stream >> field.data;
}

// The number of shares not paired at the Current Reference Price.
struct imbalance_shares {

    static constexpr auto name = "imbalance_shares";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    imbalance_shares() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const imbalance_shares& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const imbalance_shares& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, imbalance_shares& field) {
    return stream >> field.data;
}

// Interest Flag
struct interest_flag {

    static constexpr auto name = "interest_flag";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    interest_flag() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const interest_flag& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const interest_flag& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, interest_flag& field) {
    return stream >> field.data;
}

// Indicates the directional relationship between the ETP and underlying index. Example: An ETP Leverage Factor of 3 and an Inverse value of ‘Y’ indicates the ETP will decrease by a value of 3.
struct inverse_indicator {

    static constexpr auto name = "inverse_indicator";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    inverse_indicator() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const inverse_indicator& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const inverse_indicator& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, inverse_indicator& field) {
    return stream >> field.data;
}

// Indicates if the NASDAQ security is set up for IPO release.   This field is intended to help NASDAQ market participant firms comply with FINRA Rule 5131(b).
struct ipo_flag {

    static constexpr auto name = "ipo_flag";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    ipo_flag() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const ipo_flag& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const ipo_flag& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, ipo_flag& field) {
    return stream >> field.data;
}

// Denotes the IPO price to be used for intraday net change calculations. Prices are given in decimal format with 6 whole number places followed by 4 decimal digits.
struct ipo_price {

    static constexpr auto name = "ipo_price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    ipo_price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const ipo_price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const ipo_price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, ipo_price& field) {
    return stream >> field.data;
}

// Anticipated quotation release time. This value would be used when NASDAQ Market Operations initially enters the IPO instrument for release.IPO release canceled/postponed.This value would be used when NASDAQ Market Operations cancels or postpones the release of the IPO instrument.
struct ipo_quotation_release_qualifier {

    static constexpr auto name = "ipo_quotation_release_qualifier";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    ipo_quotation_release_qualifier() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const ipo_quotation_release_qualifier& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const ipo_quotation_release_qualifier& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, ipo_quotation_release_qualifier& field) {
    return stream >> field.data;
}

// Denotes the IPO release time, in seconds since midnight, for quotation to the nearest second.
struct ipo_quotation_release_time {

    static constexpr auto name = "ipo_quotation_release_time";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    ipo_quotation_release_time() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const ipo_quotation_release_time& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const ipo_quotation_release_time& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, ipo_quotation_release_time& field) {
    return stream >> field.data;
}

// Identifies the security class for the issue as assigned by NASDAQ. See Appendix for allowable values.
struct issue_classification {

    static constexpr auto name = "issue_classification";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    issue_classification() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const issue_classification& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const issue_classification& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, issue_classification& field) {
    return stream >> field.data;
}

// Identifies the security sub-type for the issue as assigned by NASDAQ. See Appendix for allowable values.
struct issue_sub_type {

    static constexpr auto name = "issue_sub_type";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 2;

    issue_sub_type() = default;

    void reset() {
        data.reset();
    }

    void set(u_char** current) {
        std::uint32_t index = 0;
        for (; index < size; ++index) {
            if (*(*current + index) == ' ') { break; }
        }
        data = std::string_view(reinterpret_cast<char *>(*current), index);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::string> data;
};

inline auto& operator<<(std::ostream& stream, const issue_sub_type& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const issue_sub_type& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, issue_sub_type& field) {
    return stream >> field.data;
}

// Denotes the MWCB Level 1 Value.
struct level_1 {

    static constexpr auto name = "level_1";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    level_1() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const level_1& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const level_1& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, level_1& field) {
    return stream >> field.data;
}

// Denotes the MWCB Level 2 Value.
struct level_2 {

    static constexpr auto name = "level_2";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    level_2() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const level_2& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const level_2& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, level_2& field) {
    return stream >> field.data;
}

// Denotes the MWCB Level 3 Value.
struct level_3 {

    static constexpr auto name = "level_3";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    level_3() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const level_3& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const level_3& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, level_3& field) {
    return stream >> field.data;
}

// Locate code identifying the security
struct locate_code {

    static constexpr auto name = "locate_code";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_16;
    static constexpr std::uint32_t size = 2;

    locate_code() = default;

    void set(u_char** current) {
        data = htobe16(*reinterpret_cast<std::uint16_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint16_t> data;
};

inline auto& operator<<(std::ostream& stream, const locate_code& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const locate_code& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, locate_code& field) {
    return stream >> field.data;
}

// Indicates the price of the Lower Auction Collar Threshold
struct lower_auction_collar_price {

    static constexpr auto name = "lower_auction_collar_price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    lower_auction_collar_price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const lower_auction_collar_price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const lower_auction_collar_price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, lower_auction_collar_price& field) {
    return stream >> field.data;
}

// Indicates which Limit Up / Limit Down price band calculation parameter is to be used for the instrument.
struct luld_reference_price_tier {

    static constexpr auto name = "luld_reference_price_tier";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    luld_reference_price_tier() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const luld_reference_price_tier& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const luld_reference_price_tier& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, luld_reference_price_tier& field) {
    return stream >> field.data;
}

// Indicates Listing market or listing market tier for the issue
struct market_category {

    static constexpr auto name = "market_category";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    market_category() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const market_category& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const market_category& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, market_category& field) {
    return stream >> field.data;
}

// Indicates the quoting participant’s registration status in relation to SEC Rules 101 and 104 of Regulation M
struct market_maker_mode {

    static constexpr auto name = "market_maker_mode";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    market_maker_mode() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const market_maker_mode& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const market_maker_mode& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, market_maker_mode& field) {
    return stream >> field.data;
}

// Indicates the market participant’s current registration status in the issue
struct market_participant_state {

    static constexpr auto name = "market_participant_state";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    market_participant_state() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const market_participant_state& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const market_participant_state& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, market_participant_state& field) {
    return stream >> field.data;
}

// The NASDAQ generated day-unique Match Number of this execution. The match number is also referenced in the Trade Break Message.
struct match_number {

    static constexpr auto name = "match_number";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    match_number() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const match_number& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const match_number& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, match_number& field) {
    return stream >> field.data;
}

// Denotes the market participant identifier for which the position message is being generated
struct mpid {

    static constexpr auto name = "mpid";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 4;

    mpid() = default;

    void reset() {
        data.reset();
    }

    void set(u_char** current) {
        std::uint32_t index = 0;
        for (; index < size; ++index) {
            if (*(*current + index) == ' ') { break; }
        }
        data = std::string_view(reinterpret_cast<char *>(*current), index);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::string> data;
};

inline auto& operator<<(std::ostream& stream, const mpid& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const mpid& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, mpid& field) {
    return stream >> field.data;
}

// A hypothetical auction-clearing price for cross orders as well as continuous orders. Refer to Data Types for field processing notes.
struct near_price {

    static constexpr auto name = "near_price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    near_price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const near_price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const near_price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, near_price& field) {
    return stream >> field.data;
}

// The new reference number for this order at time of replacement. Please note that the NASDAQ system will use this new order reference number for all subsequent updates.
struct new_order_reference_number {

    static constexpr auto name = "new_order_reference_number";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    new_order_reference_number() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const new_order_reference_number& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const new_order_reference_number& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, new_order_reference_number& field) {
    return stream >> field.data;
}

// The unique reference number assigned to the new order at the time of receipt.
struct order_reference_number {

    static constexpr auto name = "order_reference_number";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    order_reference_number() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const order_reference_number& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const order_reference_number& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, order_reference_number& field) {
    return stream >> field.data;
}

// The original reference number of the order being replaced.
struct original_order_reference_number {

    static constexpr auto name = "original_order_reference_number";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    original_order_reference_number() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const original_order_reference_number& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const original_order_reference_number& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, original_order_reference_number& field) {
    return stream >> field.data;
}

// The total number of shares that are eligible to be matched at the Current Reference Price.
struct paired_shares {

    static constexpr auto name = "paired_shares";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    paired_shares() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const paired_shares& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const paired_shares& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, paired_shares& field) {
    return stream >> field.data;
}

// The display price of the new order.  Refer to Data Types for field processing notes.
struct price {

    static constexpr auto name = "price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, price& field) {
    return stream >> field.data;
}

// This field indicates the absolute value of the percentage of deviation of the Near Indicative Clearing Price to the nearest Current Reference Price.
struct price_variation_indicator {

    static constexpr auto name = "price_variation_indicator";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    price_variation_indicator() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const price_variation_indicator& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const price_variation_indicator& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, price_variation_indicator& field) {
    return stream >> field.data;
}

// Indicates if the market participant firm qualifies as a Primary Market Maker in accordance with NASDAQ marketplace rules
struct primary_market_maker {

    static constexpr auto name = "primary_market_maker";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    primary_market_maker() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const primary_market_maker& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const primary_market_maker& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, primary_market_maker& field) {
    return stream >> field.data;
}

// Indicates if the execution should be reflected on time and sale displays and volume calculations.
struct printable {

    static constexpr auto name = "printable";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    printable() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const printable& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const printable& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, printable& field) {
    return stream >> field.data;
}

// Trading Action reason
struct reason {

    static constexpr auto name = "reason";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 4;

    reason() = default;

    void reset() {
        data.reset();
    }

    void set(u_char** current) {
        std::uint32_t index = 0;
        for (; index < size; ++index) {
            if (*(*current + index) == ' ') { break; }
        }
        data = std::string_view(reinterpret_cast<char *>(*current), index);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::string> data;
};

inline auto& operator<<(std::ostream& stream, const reason& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const reason& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, reason& field) {
    return stream >> field.data;
}

// Denotes the Reg SHO Short Sale Price Test Restriction status for the issue at the time of the message dissemination
struct reg_sho_action {

    static constexpr auto name = "reg_sho_action";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    reg_sho_action() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const reg_sho_action& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const reg_sho_action& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, reg_sho_action& field) {
    return stream >> field.data;
}

// Reserved
struct reserved {

    static constexpr auto name = "reserved";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    reserved() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const reserved& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const reserved& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, reserved& field) {
    return stream >> field.data;
}

// Denotes the number of shares that represent a round lot for the issue
struct round_lot_size {

    static constexpr auto name = "round_lot_size";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    round_lot_size() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const round_lot_size& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const round_lot_size& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, round_lot_size& field) {
    return stream >> field.data;
}

// Indicates if NASDAQ system limits order entry for issue
struct round_lots_only {

    static constexpr auto name = "round_lots_only";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    round_lots_only() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const round_lots_only& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const round_lots_only& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, round_lots_only& field) {
    return stream >> field.data;
}

// The total number of shares associated with the order being added to the book.
struct shares {

    static constexpr auto name = "shares";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    shares() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const shares& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const shares& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, shares& field) {
    return stream >> field.data;
}

// Indicates if a security is subject to mandatory close-out of short sales under SEC Rule 203(b)(3).
struct short_sale_threshold_indicator {

    static constexpr auto name = "short_sale_threshold_indicator";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    short_sale_threshold_indicator() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const short_sale_threshold_indicator& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const short_sale_threshold_indicator& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, short_sale_threshold_indicator& field) {
    return stream >> field.data;
}

// Denotes the security symbol for the issue in the NASDAQ execution system.
struct stock {

    static constexpr auto name = "stock";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 8;

    stock() = default;

    void reset() {
        data.reset();
    }

    void set(u_char** current) {
        std::uint32_t index = 0;
        for (; index < size; ++index) {
            if (*(*current + index) == ' ') { break; }
        }
        data = std::string_view(reinterpret_cast<char *>(*current), index);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::string> data;
};

inline auto& operator<<(std::ostream& stream, const stock& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const stock& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, stock& field) {
    return stream >> field.data;
}

// Always 0
struct stock_locate {

    static constexpr auto name = "stock_locate";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_16;
    static constexpr std::uint32_t size = 2;

    stock_locate() = default;

    void set(u_char** current) {
        data = htobe16(*reinterpret_cast<std::uint16_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint16_t> data;
};

inline auto& operator<<(std::ostream& stream, const stock_locate& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const stock_locate& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, stock_locate& field) {
    return stream >> field.data;
}

// Nanoseconds since midnight.
struct timestamp {

    static constexpr auto name = "timestamp";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 6;

    timestamp() = default;

    void set(u_char** current) {
        std::uint64_t value = 0;
        for( size_t i = 0; i < size; ++i ) {
            value = (value << 8) + **current;
            *current += 1;
        }
        data = value;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const timestamp& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const timestamp& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, timestamp& field) {
    return stream >> field.data;
}

// NASDAQ OMX internal tracking number
struct tracking_number {

    static constexpr auto name = "tracking_number";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_16;
    static constexpr std::uint32_t size = 2;

    tracking_number() = default;

    void set(u_char** current) {
        data = htobe16(*reinterpret_cast<std::uint16_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint16_t> data;
};

inline auto& operator<<(std::ostream& stream, const tracking_number& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const tracking_number& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, tracking_number& field) {
    return stream >> field.data;
}

// Indicates the current trading state for the stock.  Allowable values:
struct trading_state {

    static constexpr auto name = "trading_state";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    trading_state() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const trading_state& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const trading_state& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, trading_state& field) {
    return stream >> field.data;
}

// Indicates the price of the Upper Auction Collar Threshold
struct upper_auction_collar_price {

    static constexpr auto name = "upper_auction_collar_price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    upper_auction_collar_price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const upper_auction_collar_price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const upper_auction_collar_price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, upper_auction_collar_price& field) {
    return stream >> field.data;
}

///////////////////////////////////////////////////////////////////////
// itch record
///////////////////////////////////////////////////////////////////////

// Note
struct record {

    // pcap fields
    nasdaq::itch::pcap_index pcap_index;
    nasdaq::itch::pcap_timestamp pcap_timestamp;

    // header fields
    nasdaq::itch::session session;
    nasdaq::itch::message_sequence message_sequence;
    nasdaq::itch::message_index message_index;
    nasdaq::itch::message_length message_length;
    nasdaq::itch::message_type message_type;

    // message fields
    nasdaq::itch::attribution attribution;
    nasdaq::itch::auction_collar_extension auction_collar_extension;
    nasdaq::itch::auction_collar_reference_price auction_collar_reference_price;
    nasdaq::itch::authenticity authenticity;
    nasdaq::itch::breached_level breached_level;
    nasdaq::itch::buy_sell_indicator buy_sell_indicator;
    nasdaq::itch::canceled_shares canceled_shares;
    nasdaq::itch::cross_price cross_price;
    nasdaq::itch::cross_shares cross_shares;
    nasdaq::itch::cross_type cross_type;
    nasdaq::itch::current_reference_price current_reference_price;
    nasdaq::itch::etp_flag etp_flag;
    nasdaq::itch::etp_leverage_factor etp_leverage_factor;
    nasdaq::itch::event_code event_code;
    nasdaq::itch::executed_shares executed_shares;
    nasdaq::itch::execution_price execution_price;
    nasdaq::itch::far_price far_price;
    nasdaq::itch::financial_status_indicator financial_status_indicator;
    nasdaq::itch::imbalance_direction imbalance_direction;
    nasdaq::itch::imbalance_shares imbalance_shares;
    nasdaq::itch::interest_flag interest_flag;
    nasdaq::itch::inverse_indicator inverse_indicator;
    nasdaq::itch::ipo_flag ipo_flag;
    nasdaq::itch::ipo_price ipo_price;
    nasdaq::itch::ipo_quotation_release_qualifier ipo_quotation_release_qualifier;
    nasdaq::itch::ipo_quotation_release_time ipo_quotation_release_time;
    nasdaq::itch::issue_classification issue_classification;
    nasdaq::itch::issue_sub_type issue_sub_type;
    nasdaq::itch::level_1 level_1;
    nasdaq::itch::level_2 level_2;
    nasdaq::itch::level_3 level_3;
    nasdaq::itch::locate_code locate_code;
    nasdaq::itch::lower_auction_collar_price lower_auction_collar_price;
    nasdaq::itch::luld_reference_price_tier luld_reference_price_tier;
    nasdaq::itch::market_category market_category;
    nasdaq::itch::market_maker_mode market_maker_mode;
    nasdaq::itch::market_participant_state market_participant_state;
    nasdaq::itch::match_number match_number;
    nasdaq::itch::mpid mpid;
    nasdaq::itch::near_price near_price;
    nasdaq::itch::new_order_reference_number new_order_reference_number;
    nasdaq::itch::order_reference_number order_reference_number;
    nasdaq::itch::original_order_reference_number original_order_reference_number;
    nasdaq::itch::paired_shares paired_shares;
    nasdaq::itch::price price;
    nasdaq::itch::price_variation_indicator price_variation_indicator;
    nasdaq::itch::primary_market_maker primary_market_maker;
    nasdaq::itch::printable printable;
    nasdaq::itch::reason reason;
    nasdaq::itch::reg_sho_action reg_sho_action;
    nasdaq::itch::reserved reserved;
    nasdaq::itch::round_lot_size round_lot_size;
    nasdaq::itch::round_lots_only round_lots_only;
    nasdaq::itch::shares shares;
    nasdaq::itch::short_sale_threshold_indicator short_sale_threshold_indicator;
    nasdaq::itch::stock stock;
    nasdaq::itch::stock_locate stock_locate;
    nasdaq::itch::timestamp timestamp;
    nasdaq::itch::tracking_number tracking_number;
    nasdaq::itch::trading_state trading_state;
    nasdaq::itch::upper_auction_collar_price upper_auction_collar_price;

    record() = default;

    // reset composite message record
    void reset() {
        attribution.reset();
        auction_collar_extension.reset();
        auction_collar_reference_price.reset();
        authenticity.reset();
        breached_level.reset();
        buy_sell_indicator.reset();
        canceled_shares.reset();
        cross_price.reset();
        cross_shares.reset();
        cross_type.reset();
        current_reference_price.reset();
        etp_flag.reset();
        etp_leverage_factor.reset();
        event_code.reset();
        executed_shares.reset();
        execution_price.reset();
        far_price.reset();
        financial_status_indicator.reset();
        imbalance_direction.reset();
        imbalance_shares.reset();
        interest_flag.reset();
        inverse_indicator.reset();
        ipo_flag.reset();
        ipo_price.reset();
        ipo_quotation_release_qualifier.reset();
        ipo_quotation_release_time.reset();
        issue_classification.reset();
        issue_sub_type.reset();
        level_1.reset();
        level_2.reset();
        level_3.reset();
        locate_code.reset();
        lower_auction_collar_price.reset();
        luld_reference_price_tier.reset();
        market_category.reset();
        market_maker_mode.reset();
        market_participant_state.reset();
        match_number.reset();
        mpid.reset();
        near_price.reset();
        new_order_reference_number.reset();
        order_reference_number.reset();
        original_order_reference_number.reset();
        paired_shares.reset();
        price.reset();
        price_variation_indicator.reset();
        primary_market_maker.reset();
        printable.reset();
        reason.reset();
        reg_sho_action.reset();
        reserved.reset();
        round_lot_size.reset();
        round_lots_only.reset();
        shares.reset();
        short_sale_threshold_indicator.reset();
        stock.reset();
        stock_locate.reset();
        timestamp.reset();
        tracking_number.reset();
        trading_state.reset();
        upper_auction_collar_price.reset();
    }

    // parquet schema nodes
    static auto nodes() {
        return parquet::schema::NodeVector {
            nasdaq::itch::pcap_index::node(),
            nasdaq::itch::pcap_timestamp::node(),
            nasdaq::itch::session::node(),
            nasdaq::itch::message_sequence::node(),
            nasdaq::itch::message_index::node(),
            nasdaq::itch::message_type::node(),
            nasdaq::itch::attribution::node(),
            nasdaq::itch::auction_collar_extension::node(),
            nasdaq::itch::auction_collar_reference_price::node(),
            nasdaq::itch::authenticity::node(),
            nasdaq::itch::breached_level::node(),
            nasdaq::itch::buy_sell_indicator::node(),
            nasdaq::itch::canceled_shares::node(),
            nasdaq::itch::cross_price::node(),
            nasdaq::itch::cross_shares::node(),
            nasdaq::itch::cross_type::node(),
            nasdaq::itch::current_reference_price::node(),
            nasdaq::itch::etp_flag::node(),
            nasdaq::itch::etp_leverage_factor::node(),
            nasdaq::itch::event_code::node(),
            nasdaq::itch::executed_shares::node(),
            nasdaq::itch::execution_price::node(),
            nasdaq::itch::far_price::node(),
            nasdaq::itch::financial_status_indicator::node(),
            nasdaq::itch::imbalance_direction::node(),
            nasdaq::itch::imbalance_shares::node(),
            nasdaq::itch::interest_flag::node(),
            nasdaq::itch::inverse_indicator::node(),
            nasdaq::itch::ipo_flag::node(),
            nasdaq::itch::ipo_price::node(),
            nasdaq::itch::ipo_quotation_release_qualifier::node(),
            nasdaq::itch::ipo_quotation_release_time::node(),
            nasdaq::itch::issue_classification::node(),
            nasdaq::itch::issue_sub_type::node(),
            nasdaq::itch::level_1::node(),
            nasdaq::itch::level_2::node(),
            nasdaq::itch::level_3::node(),
            nasdaq::itch::locate_code::node(),
            nasdaq::itch::lower_auction_collar_price::node(),
            nasdaq::itch::luld_reference_price_tier::node(),
            nasdaq::itch::market_category::node(),
            nasdaq::itch::market_maker_mode::node(),
            nasdaq::itch::market_participant_state::node(),
            nasdaq::itch::match_number::node(),
            nasdaq::itch::mpid::node(),
            nasdaq::itch::near_price::node(),
            nasdaq::itch::new_order_reference_number::node(),
            nasdaq::itch::order_reference_number::node(),
            nasdaq::itch::original_order_reference_number::node(),
            nasdaq::itch::paired_shares::node(),
            nasdaq::itch::price::node(),
            nasdaq::itch::price_variation_indicator::node(),
            nasdaq::itch::primary_market_maker::node(),
            nasdaq::itch::printable::node(),
            nasdaq::itch::reason::node(),
            nasdaq::itch::reg_sho_action::node(),
            nasdaq::itch::reserved::node(),
            nasdaq::itch::round_lot_size::node(),
            nasdaq::itch::round_lots_only::node(),
            nasdaq::itch::shares::node(),
            nasdaq::itch::short_sale_threshold_indicator::node(),
            nasdaq::itch::stock::node(),
            nasdaq::itch::stock_locate::node(),
            nasdaq::itch::timestamp::node(),
            nasdaq::itch::tracking_number::node(),
            nasdaq::itch::trading_state::node(),
            nasdaq::itch::upper_auction_collar_price::node()
        };
    }

    // parquet schema
    static auto schema() {
        return std::static_pointer_cast<parquet::schema::GroupNode>(parquet::schema::GroupNode::Make("schema", parquet::Repetition::REQUIRED, nodes()));
    }
};

inline auto& operator<<(parquet::StreamWriter& stream, const record& row) {
    return stream
        << row.pcap_index
        << row.pcap_timestamp
        << row.session
        << row.message_sequence
        << row.message_index
        << row.message_type
        << row.attribution
        << row.auction_collar_extension
        << row.auction_collar_reference_price
        << row.authenticity
        << row.breached_level
        << row.buy_sell_indicator
        << row.canceled_shares
        << row.cross_price
        << row.cross_shares
        << row.cross_type
        << row.current_reference_price
        << row.etp_flag
        << row.etp_leverage_factor
        << row.event_code
        << row.executed_shares
        << row.execution_price
        << row.far_price
        << row.financial_status_indicator
        << row.imbalance_direction
        << row.imbalance_shares
        << row.interest_flag
        << row.inverse_indicator
        << row.ipo_flag
        << row.ipo_price
        << row.ipo_quotation_release_qualifier
        << row.ipo_quotation_release_time
        << row.issue_classification
        << row.issue_sub_type
        << row.level_1
        << row.level_2
        << row.level_3
        << row.locate_code
        << row.lower_auction_collar_price
        << row.luld_reference_price_tier
        << row.market_category
        << row.market_maker_mode
        << row.market_participant_state
        << row.match_number
        << row.mpid
        << row.near_price
        << row.new_order_reference_number
        << row.order_reference_number
        << row.original_order_reference_number
        << row.paired_shares
        << row.price
        << row.price_variation_indicator
        << row.primary_market_maker
        << row.printable
        << row.reason
        << row.reg_sho_action
        << row.reserved
        << row.round_lot_size
        << row.round_lots_only
        << row.shares
        << row.short_sale_threshold_indicator
        << row.stock
        << row.stock_locate
        << row.timestamp
        << row.tracking_number
        << row.trading_state
        << row.upper_auction_collar_price
        << parquet::EndRow;
}

inline auto& operator>>(parquet::StreamReader& stream, record& row) {
    return stream
        >> row.pcap_index
        >> row.pcap_timestamp
        >> row.session
        >> row.message_sequence
        >> row.message_index
        >> row.message_type
        >> row.attribution
        >> row.auction_collar_extension
        >> row.auction_collar_reference_price
        >> row.authenticity
        >> row.breached_level
        >> row.buy_sell_indicator
        >> row.canceled_shares
        >> row.cross_price
        >> row.cross_shares
        >> row.cross_type
        >> row.current_reference_price
        >> row.etp_flag
        >> row.etp_leverage_factor
        >> row.event_code
        >> row.executed_shares
        >> row.execution_price
        >> row.far_price
        >> row.financial_status_indicator
        >> row.imbalance_direction
        >> row.imbalance_shares
        >> row.interest_flag
        >> row.inverse_indicator
        >> row.ipo_flag
        >> row.ipo_price
        >> row.ipo_quotation_release_qualifier
        >> row.ipo_quotation_release_time
        >> row.issue_classification
        >> row.issue_sub_type
        >> row.level_1
        >> row.level_2
        >> row.level_3
        >> row.locate_code
        >> row.lower_auction_collar_price
        >> row.luld_reference_price_tier
        >> row.market_category
        >> row.market_maker_mode
        >> row.market_participant_state
        >> row.match_number
        >> row.mpid
        >> row.near_price
        >> row.new_order_reference_number
        >> row.order_reference_number
        >> row.original_order_reference_number
        >> row.paired_shares
        >> row.price
        >> row.price_variation_indicator
        >> row.primary_market_maker
        >> row.printable
        >> row.reason
        >> row.reg_sho_action
        >> row.reserved
        >> row.round_lot_size
        >> row.round_lots_only
        >> row.shares
        >> row.short_sale_threshold_indicator
        >> row.stock
        >> row.stock_locate
        >> row.timestamp
        >> row.tracking_number
        >> row.trading_state
        >> row.upper_auction_collar_price
        >> parquet::EndRow;
}

inline auto& operator<<(std::ostream& stream, const record& row) {
    return stream
        << row.pcap_index <<","
        << row.pcap_timestamp <<","
        << row.session <<","
        << row.message_sequence <<","
        << row.message_index <<","
        << row.message_type <<","
        << row.attribution <<","
        << row.auction_collar_extension <<","
        << row.auction_collar_reference_price <<","
        << row.authenticity <<","
        << row.breached_level <<","
        << row.buy_sell_indicator <<","
        << row.canceled_shares <<","
        << row.cross_price <<","
        << row.cross_shares <<","
        << row.cross_type <<","
        << row.current_reference_price <<","
        << row.etp_flag <<","
        << row.etp_leverage_factor <<","
        << row.event_code <<","
        << row.executed_shares <<","
        << row.execution_price <<","
        << row.far_price <<","
        << row.financial_status_indicator <<","
        << row.imbalance_direction <<","
        << row.imbalance_shares <<","
        << row.interest_flag <<","
        << row.inverse_indicator <<","
        << row.ipo_flag <<","
        << row.ipo_price <<","
        << row.ipo_quotation_release_qualifier <<","
        << row.ipo_quotation_release_time <<","
        << row.issue_classification <<","
        << row.issue_sub_type <<","
        << row.level_1 <<","
        << row.level_2 <<","
        << row.level_3 <<","
        << row.locate_code <<","
        << row.lower_auction_collar_price <<","
        << row.luld_reference_price_tier <<","
        << row.market_category <<","
        << row.market_maker_mode <<","
        << row.market_participant_state <<","
        << row.match_number <<","
        << row.mpid <<","
        << row.near_price <<","
        << row.new_order_reference_number <<","
        << row.order_reference_number <<","
        << row.original_order_reference_number <<","
        << row.paired_shares <<","
        << row.price <<","
        << row.price_variation_indicator <<","
        << row.primary_market_maker <<","
        << row.printable <<","
        << row.reason <<","
        << row.reg_sho_action <<","
        << row.reserved <<","
        << row.round_lot_size <<","
        << row.round_lots_only <<","
        << row.shares <<","
        << row.short_sale_threshold_indicator <<","
        << row.stock <<","
        << row.stock_locate <<","
        << row.timestamp <<","
        << row.tracking_number <<","
        << row.trading_state <<","
        << row.upper_auction_collar_price <<","
        << std::endl;
}
}

///////////////////////////////////////////////////////////////////////
// itch converter
///////////////////////////////////////////////////////////////////////

// parquet options
struct options {
    std::string pcap_file = "itch.pcap";
    std::string parquet_file = "itch.parquet";
    std::int64_t max_row_group_size = 1000;
};

// itch converter
struct converter {

    nasdaq::itch::record record;
    parquet::StreamWriter writer;
    std::shared_ptr<arrow::io::FileOutputStream> outfile;
    std::shared_ptr<parquet::schema::GroupNode> schema;
    parquet::WriterProperties::Builder builder;

    explicit converter(const options& options) : record{} {
        PARQUET_ASSIGN_OR_THROW(outfile, arrow::io::FileOutputStream::Open(options.parquet_file));
        schema = nasdaq::itch::record::schema();
        writer = parquet::StreamWriter{parquet::ParquetFileWriter::Open(outfile, schema, builder.build())};
        writer.SetMaxRowGroupSize(options.max_row_group_size);
    }

    // return udp payload and length by skipping headers in a packet
    bool try_get_nasdaq_itch(const u_char *packet, u_char **payload, std::int32_t *length) {

        record.pcap_index.increment();

        *payload = const_cast<u_char*>(packet);

        // ethernet header
        *payload += 12;

        while (ntohs(*reinterpret_cast<const u_short*>(*payload)) != ETHERTYPE_IP) {
            *payload += 4;
        }
        *payload += 2;

        // internet protocol header
        auto ipheader = reinterpret_cast<const ip*>(*payload);
        u_int ip_length = ipheader->ip_hl * 4;
        *payload += ip_length;

        // found upd
        if (ipheader->ip_p == IPPROTO_UDP) {
            auto udp = reinterpret_cast<const udphdr*>(*payload);
            auto udphdr_length = sizeof(udphdr);
            *length = ntohs(udp->uh_ulen) - udphdr_length;
            *payload += udphdr_length;

            return true;
        }

        *length = 0;
        *payload = nullptr;

        return false;
    }

    // process itch packet
    void process(const pcap_pkthdr* header, const u_char* packet) {

        std::int32_t length = 0;
        u_char* current = nullptr;
        u_char* message = nullptr;

        if (try_get_nasdaq_itch(packet, &current, &length)) {

            record.pcap_timestamp.set(header);

            record.session.set(&current);
            record.message_sequence.set(&current);
            record.message_index.set(&current);

            while (record.message_index.increment()) {

                record.reset();

                record.message_length.set(&current, &message);
                record.message_type.set(&message);
                record.message_sequence.increment();

                process(&message, record.message_type.data);

                writer << record;
            }
        }
    }

    void process(u_char **message, const char message_type) {
        switch (message_type) {
            case 'S':
                process_system_event_message(message);
                break;

            case 'R':
                process_stock_directory_message(message);
                break;

            case 'H':
                process_stock_trading_action_message(message);
                break;

            case 'Y':
                process_reg_sho_short_sale_price_test_restricted_indicator_message(message);
                break;

            case 'L':
                process_market_participant_position_message(message);
                break;

            case 'V':
                process_mwcb_decline_level_message(message);
                break;

            case 'W':
                process_mwcb_status_level_message(message);
                break;

            case 'K':
                process_ipo_quoting_period_update(message);
                break;

            case 'A':
                process_add_order_no_mpid_attribution_message(message);
                break;

            case 'J':
                process_luld_auction_collar_message(message);
                break;

            case 'F':
                process_add_order_with_mpid_attribution_message(message);
                break;

            case 'E':
                process_order_executed_message(message);
                break;

            case 'C':
                process_order_executed_with_price_message(message);
                break;

            case 'X':
                process_order_cancel_message(message);
                break;

            case 'D':
                process_order_delete_message(message);
                break;

            case 'U':
                process_order_replace_message(message);
                break;

            case 'P':
                process_non_cross_trade_message(message);
                break;

            case 'Q':
                process_cross_trade_message(message);
                break;

            case 'B':
                process_broken_trade_message(message);
                break;

            case 'I':
                process_net_order_imbalance_indicator_message(message);
                break;

            case 'N':
                process_retail_interest_message(message);
                break;

            default:
                break;
        }
    }

    void process_add_order_no_mpid_attribution_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.order_reference_number.set(message);
        record.buy_sell_indicator.set(message);
        record.shares.set(message);
        record.stock.set(message);
        record.price.set(message);
    }

    void process_add_order_with_mpid_attribution_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.order_reference_number.set(message);
        record.buy_sell_indicator.set(message);
        record.shares.set(message);
        record.stock.set(message);
        record.price.set(message);
        record.attribution.set(message);
    }

    void process_broken_trade_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.match_number.set(message);
    }

    void process_cross_trade_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.cross_shares.set(message);
        record.stock.set(message);
        record.cross_price.set(message);
        record.match_number.set(message);
        record.cross_type.set(message);
    }

    void process_ipo_quoting_period_update(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.stock.set(message);
        record.ipo_quotation_release_time.set(message);
        record.ipo_quotation_release_qualifier.set(message);
        record.ipo_price.set(message);
    }

    void process_luld_auction_collar_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.stock.set(message);
        record.auction_collar_reference_price.set(message);
        record.upper_auction_collar_price.set(message);
        record.lower_auction_collar_price.set(message);
        record.auction_collar_extension.set(message);
    }

    void process_market_participant_position_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.mpid.set(message);
        record.stock.set(message);
        record.primary_market_maker.set(message);
        record.market_maker_mode.set(message);
        record.market_participant_state.set(message);
    }

    void process_mwcb_decline_level_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.level_1.set(message);
        record.level_2.set(message);
        record.level_3.set(message);
    }

    void process_mwcb_status_level_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.breached_level.set(message);
    }

    void process_net_order_imbalance_indicator_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.paired_shares.set(message);
        record.imbalance_shares.set(message);
        record.imbalance_direction.set(message);
        record.stock.set(message);
        record.far_price.set(message);
        record.near_price.set(message);
        record.current_reference_price.set(message);
        record.cross_type.set(message);
        record.price_variation_indicator.set(message);
    }

    void process_non_cross_trade_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.order_reference_number.set(message);
        record.buy_sell_indicator.set(message);
        record.shares.set(message);
        record.stock.set(message);
        record.price.set(message);
        record.match_number.set(message);
    }

    void process_order_cancel_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.order_reference_number.set(message);
        record.canceled_shares.set(message);
    }

    void process_order_delete_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.order_reference_number.set(message);
    }

    void process_order_executed_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.order_reference_number.set(message);
        record.executed_shares.set(message);
        record.match_number.set(message);
    }

    void process_order_executed_with_price_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.order_reference_number.set(message);
        record.executed_shares.set(message);
        record.match_number.set(message);
        record.printable.set(message);
        record.execution_price.set(message);
    }

    void process_order_replace_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.original_order_reference_number.set(message);
        record.new_order_reference_number.set(message);
        record.shares.set(message);
        record.price.set(message);
    }

    void process_reg_sho_short_sale_price_test_restricted_indicator_message(u_char **message) {
        record.locate_code.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.stock.set(message);
        record.reg_sho_action.set(message);
    }

    void process_retail_interest_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.stock.set(message);
        record.interest_flag.set(message);
    }

    void process_stock_directory_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.stock.set(message);
        record.market_category.set(message);
        record.financial_status_indicator.set(message);
        record.round_lot_size.set(message);
        record.round_lots_only.set(message);
        record.issue_classification.set(message);
        record.issue_sub_type.set(message);
        record.authenticity.set(message);
        record.short_sale_threshold_indicator.set(message);
        record.ipo_flag.set(message);
        record.luld_reference_price_tier.set(message);
        record.etp_flag.set(message);
        record.etp_leverage_factor.set(message);
        record.inverse_indicator.set(message);
    }

    void process_stock_trading_action_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.stock.set(message);
        record.trading_state.set(message);
        record.reserved.set(message);
        record.reason.set(message);
    }

    void process_system_event_message(u_char **message) {
        record.stock_locate.set(message);
        record.tracking_number.set(message);
        record.timestamp.set(message);
        record.event_code.set(message);
    }

    // required to finish parquet file
    void close() {
        writer << parquet::EndRowGroup;
    }
};

void write_parquet(const options& options) {
    // open capture file
    char buffer[PCAP_ERRBUF_SIZE];
    const auto pcap = pcap_open_offline(options.pcap_file.c_str(), buffer);
    if (pcap == nullptr)
    {
        throw std::runtime_error("Unable to open file "); // need to add buffer
    }

    converter converter(options);

    // loop through packets
    pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        switch (pcap_next_ex(pcap, &header, &packet)) {
        case 1:
            converter.process(header, packet);
            break;
        case 0:
            // timeout
        case -1:
            //     std::cerr << "Error: " << pcap_geterr(p) << std::endl;
        case -2:
            // end-of-file
        default:
            converter.close();
            pcap_close(pcap);
            return;
        }
    }
}

void read_parquet(const std::string& parquet_file) {
    std::shared_ptr<arrow::io::ReadableFile> infile;

    PARQUET_ASSIGN_OR_THROW(infile, arrow::io::ReadableFile::Open(parquet_file));

    parquet::StreamReader reader{ parquet::ParquetFileReader::Open(infile) };

    nasdaq::itch::record record{};

    while (!reader.eof()) {
        reader >> record;
        std::cout << record;
    }
}

int main(const int argc, char** argv) {

    // parse arguments
    options options;

    if (argc == 3)
    {
        options.pcap_file = argv[1];
        options.parquet_file = argv[2];
    }
    else if (argc == 2)
    {
        options.pcap_file = argv[1];
    }
    else
    {
        std::cout << "usage: " << argv[0] << " pcap_file parquet_file" << std::endl;
        return -1;
    }

    write_parquet(options);

    read_parquet(options.parquet_file);

    return 0;
}