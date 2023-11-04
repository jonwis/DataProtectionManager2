#include "pch.h"
#include "DataProtectionProvider.h"

DataProtectionProvider::DataProtectionProvider(std::wstring const& scope)
{
    THROW_IF_WIN32_ERROR(::NCryptCreateProtectionDescriptor(
        scope.c_str(),
        0,
        &m_descriptor));
}

DataProtectionBuffer DataProtectionProvider::ProtectBuffer(std::span<uint8_t const> data)
{
    wil::unique_hlocal_ptr<> protectedData;
    ULONG protectedSize = 0;
    THROW_IF_WIN32_ERROR(::NCryptProtectSecret(
        m_descriptor,
        0,
        data.data(),
        static_cast<ULONG>(data.size()),
        nullptr,
        nullptr,
        reinterpret_cast<BYTE**>(&protectedData),
        &protectedSize));

    return { std::move(protectedData), protectedSize };
}

DataProtectionBuffer DataProtectionProvider::UnprotectBuffer(std::span<uint8_t const> data)
{
    wil::unique_hlocal_ptr<> unprotectedData;
    ULONG unprotectedSize = 0;
    THROW_IF_WIN32_ERROR(::NCryptUnprotectSecret(
        nullptr,
        0,
        data.data(),
        static_cast<ULONG>(data.size()),
        nullptr,
        nullptr,
        reinterpret_cast<BYTE**>(&unprotectedData),
        &unprotectedSize));

    return { std::move(unprotectedData), unprotectedSize };
}

winrt::com_ptr<DataProtectionStreamWriter> DataProtectionProvider::CreateEncryptionStreamWriter(::IStream* outputStream)
{
    return winrt::make_self<DataProtectionStreamWriter>(m_descriptor, outputStream);
}

winrt::com_ptr<DataProtectionStreamWriter> DataProtectionProvider::CreateDecryptionStreamWriter(::IStream* outputStream)
{
    return winrt::make_self<DataProtectionStreamWriter>(outputStream);
}

DataProtectionProvider::~DataProtectionProvider()
{
    if (m_descriptor)
    {
        NCryptCloseProtectionDescriptor(m_descriptor);
    }
}

DataProtectionStreamWriter::DataProtectionStreamWriter(NCRYPT_DESCRIPTOR_HANDLE encryptionDescriptor, IStream* lower)
{
    ConfigureStreamInfo(lower);
    THROW_IF_WIN32_ERROR(::NCryptStreamOpenToProtect(encryptionDescriptor, 0, nullptr, &m_streamInfo, &m_handle));
}

DataProtectionStreamWriter::DataProtectionStreamWriter(IStream* lower)
{
    ConfigureStreamInfo(lower);
    THROW_IF_WIN32_ERROR(::NCryptStreamOpenToUnprotect(&m_streamInfo, 0, nullptr, &m_handle));
}

void DataProtectionStreamWriter::ConfigureStreamInfo(IStream* lower)
{
    m_lower = lower;
    m_streamInfo.pvCallbackCtxt = this;
    m_streamInfo.pfnStreamOutput = [](void* context, BYTE const* data, SIZE_T size, BOOL) -> SECURITY_STATUS
        {
            auto self = static_cast<DataProtectionStreamWriter*>(context);
            RETURN_IF_FAILED(self->m_writeError = wil::stream_write_nothrow(self->m_lower.get(), data, static_cast<ULONG>(size)));
            return 0;
        };
}

void DataProtectionStreamWriter::finish()
{
    if (auto h = std::exchange(m_handle, {}))
    {
        THROW_IF_WIN32_ERROR(::NCryptStreamUpdate(h, nullptr, 0, TRUE));
        THROW_IF_WIN32_ERROR(::NCryptStreamClose(h));
    }
}

STDMETHODIMP DataProtectionStreamWriter::Write(void const* pv, ULONG size, ULONG* pcbWritten) noexcept
{
    RETURN_HR_IF(E_UNEXPECTED, !m_handle);
    RETURN_IF_WIN32_ERROR(::NCryptStreamUpdate(m_handle, reinterpret_cast<BYTE const*>(pv), size, FALSE));
    wil::assign_to_opt_param(pcbWritten, size);
    return S_OK;
}

STDMETHODIMP DataProtectionStreamWriter::Read(void*, ULONG, ULONG* read) noexcept
{
    *read = 0;
    return E_NOTIMPL;
}

STDMETHODIMP DataProtectionStreamWriter::Commit(ULONG) noexcept
{
    return S_OK;
}

STDMETHODIMP DataProtectionStreamWriter::Revert() noexcept
{
    return E_NOTIMPL;
}

STDMETHODIMP DataProtectionStreamWriter::Seek(LARGE_INTEGER, DWORD, ULARGE_INTEGER* newPos) noexcept
{
    wil::assign_to_opt_param(newPos, {});
    return E_NOTIMPL;
}

STDMETHODIMP DataProtectionStreamWriter::SetSize(ULARGE_INTEGER) noexcept
{
    return E_NOTIMPL;
}

STDMETHODIMP DataProtectionStreamWriter::CopyTo(::IStream*, ULARGE_INTEGER, ULARGE_INTEGER* read, ULARGE_INTEGER* written) noexcept
{
    wil::assign_to_opt_param(read, {});
    wil::assign_to_opt_param(written, {});
    return E_NOTIMPL;
}

STDMETHODIMP DataProtectionStreamWriter::Clone(IStream** result) noexcept
{
    wil::assign_null_to_opt_param(result);
    return E_NOTIMPL;
}

STDMETHODIMP DataProtectionStreamWriter::Stat(STATSTG* stats, DWORD) noexcept
{
    *stats = {};
    return E_NOTIMPL;
}

STDMETHODIMP DataProtectionStreamWriter::LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept
{
    return E_NOTIMPL;
}

STDMETHODIMP DataProtectionStreamWriter::UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept
{
    return E_NOTIMPL;
}
