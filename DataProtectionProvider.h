#pragma once

#include <Unknwn.h>
#include <string>
#include <span>
#include <wil/resource.h>
#include <wil/com.h>
#include <winrt/base.h>
#include <ncryptprotect.h>

struct DataProtectionBuffer
{
    DataProtectionBuffer() = default;
    DataProtectionBuffer(DataProtectionBuffer const&) = delete;
    DataProtectionBuffer& operator=(DataProtectionBuffer const&) = delete;

    DataProtectionBuffer(wil::unique_hlocal_ptr<> data, uint32_t size) : m_data(std::move(data)), m_size(size)
    {
    }

    DataProtectionBuffer(DataProtectionBuffer&&) = default;
    DataProtectionBuffer& operator=(DataProtectionBuffer&&) = default;

    ~DataProtectionBuffer() = default;

    template<typename T> auto as_span() const
    {
        return std::span<T const>{reinterpret_cast<T const*>(m_data.get()), m_size / sizeof(T) };
    }

    void const* data() const { return m_data.get(); }
    uint32_t size() const { return m_size; }

private:
    wil::unique_hlocal_ptr<> m_data{};
    uint32_t m_size{};
};

struct DataProtectionStreamWriter : winrt::implements<DataProtectionStreamWriter, ::IStream, ::ISequentialStream>
{
    DataProtectionStreamWriter(NCRYPT_DESCRIPTOR_HANDLE encryptionDescriptor, IStream* lower);
    DataProtectionStreamWriter(IStream* lower);
    void finish();

protected:
    STDMETHODIMP Write(void const* pv, ULONG size, ULONG* pcbWritten) noexcept override;
    STDMETHODIMP Read(void*, ULONG, ULONG* read) noexcept override;
    STDMETHODIMP Commit(ULONG) noexcept override;
    STDMETHODIMP Revert() noexcept override;
    STDMETHODIMP Seek(LARGE_INTEGER, DWORD, ULARGE_INTEGER* newPos) noexcept override;
    STDMETHODIMP SetSize(ULARGE_INTEGER) noexcept override;
    STDMETHODIMP CopyTo(::IStream*, ULARGE_INTEGER, ULARGE_INTEGER* read, ULARGE_INTEGER* written) noexcept override;
    STDMETHODIMP Clone(IStream** result) noexcept override;
    STDMETHODIMP Stat(STATSTG* stats, DWORD) noexcept override;
    STDMETHODIMP LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept override;
    STDMETHODIMP UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept override;

private:
    void ConfigureStreamInfo(IStream* lower);
    wil::com_ptr<::IStream> m_lower{ nullptr };
    HRESULT m_writeError{ S_OK };
    NCRYPT_STREAM_HANDLE m_handle{ nullptr };
    NCRYPT_PROTECT_STREAM_INFO m_streamInfo{};
};

struct DataProtectionProvider
{
    DataProtectionProvider(std::wstring const& scope = L"LOCAL=user");

    // Takes a buffer of cleartext data and returns an ecrypted buffer of data based on the protection
    // scope specified in the constructor.
    DataProtectionBuffer ProtectBuffer(std::span<uint8_t const> data);

    // Takes a buffer of encrypted data and returns a cleartext buffer after decrypting it. Note that
    // protected buffers include their decryption scope. No error occurs if you attempt to decrypt a
    // buffer that was not encrypted with the same scope as the current provider.
    DataProtectionBuffer UnprotectBuffer(std::span<uint8_t const> data);

    // Creates an encryption filter stream. Writing cleartext data into the writer
    // pushes encrypted data into the 'output' stream on the other side. Be sure
    // to call "writer->finish()" to complete the encryption operation. The returned
    // stream object is-an IStream & ISequentialStream, suitable for passing to other
    // methods that write to it. Note that it is write-only; any attempt to read from
    // the stream or seek it will fail.
    winrt::com_ptr<DataProtectionStreamWriter> CreateEncryptionStreamWriter(::IStream* outputStream);

    // Creates a decryption filter stream. Writing encrypted data into the writer
    // pushes cleartext data into the 'output' stream on the other side. Be sure
    // to call "writer->finish()" to complete the decryption operation. The returned
    // stream object is-an IStream & ISequentialStream, suitable for passing to other
    // methods that write to it. Note that it is write-only; any attempt to read from
    // the stream or seek it will fail.
    winrt::com_ptr<DataProtectionStreamWriter> CreateDecryptionStreamWriter(::IStream* outputStream);

    ~DataProtectionProvider();

private:
    NCRYPT_DESCRIPTOR_HANDLE m_descriptor{ nullptr };
};

// Given an encrypted stream, this type will decrypt it on the fly as it is read. Note that
// this type is forward-sequential-read-only and cannot be seek'd or written to. Many APIs that
// take an IStream really only need ISequentialStream, so this type can be used in those cases.
struct DecryptionReadStream : winrt::implements<DecryptionReadStream, IStream, ISequentialStream>
{
public:

    DecryptionReadStream(IStream* encryptedSource);
    ~DecryptionReadStream();

protected:

    STDMETHODIMP Read(void* pv, ULONG size, ULONG* read) noexcept override;
    STDMETHODIMP Write(void const*, ULONG, ULONG* pcbWritten) noexcept override;
    STDMETHODIMP Commit(ULONG) noexcept override;
    STDMETHODIMP Revert() noexcept override;
    STDMETHODIMP Seek(LARGE_INTEGER, DWORD, ULARGE_INTEGER* newPos) noexcept override;
    STDMETHODIMP SetSize(ULARGE_INTEGER) noexcept override;
    STDMETHODIMP CopyTo(::IStream*, ULARGE_INTEGER, ULARGE_INTEGER* read, ULARGE_INTEGER* written) noexcept override;
    STDMETHODIMP Clone(IStream** result) noexcept override;
    STDMETHODIMP Stat(STATSTG* stats, DWORD) noexcept override;
    STDMETHODIMP LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept override;
    STDMETHODIMP UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept override;

private:
    void EnsureAvailableBytes(size_t desiredSize);

    bool m_finalBlockRead{ false };
    std::vector<uint8_t> m_pendingData;
    wil::com_ptr<IStream> m_source;
    NCRYPT_STREAM_HANDLE m_streamHandle{ nullptr };
    NCRYPT_PROTECT_STREAM_INFO m_streamInfo{};
    uint64_t m_dataReadSoFar{ 0 };
    std::array<uint8_t, 64 * 1024> m_sourceReadBuffer{};
};
